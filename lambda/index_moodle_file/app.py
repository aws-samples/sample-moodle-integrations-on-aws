"""Lambda function for indexing Moodle files into AWS Bedrock Knowledge Base.

This module processes EventBridge events triggered when files are added or updated
in Moodle courses. It downloads the files from Moodle and indexes them into an
AWS Bedrock Knowledge Base for AI-powered search and retrieval.

The workflow is:
1. Receives EventBridge event with course ID and module ID
2. Fetches course content information from Moodle API
3. Locates the specific module that triggered the event
4. Downloads any files in that module from Moodle
5. Indexes the files into AWS Bedrock Knowledge Base
6. Handles errors and retries appropriately

Required environment variables:
- MOODLE_DNS: DNS name of Moodle server
- KNOWLEDGE_BASE_ID: ID of AWS Bedrock Knowledge Base
- DATA_SOURCE_ID: ID of data source in Knowledge Base
- MOODLE_TOKEN_SECRET_NAME: Name of secret containing Moodle API token
"""

import requests
import json
import os
import tempfile
import boto3
import re
import secrets
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities import parameters
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.data_classes import EventBridgeEvent, event_source


logger = Logger()
tracer = Tracer()


bedrock_agent_client = boto3.client("bedrock-agent")

MOODLE_URL = f"https://{os.environ['MOODLE_DNS']}"
KNOWLEDGE_BASE_ID = os.environ["KNOWLEDGE_BASE_ID"]
DATA_SOURCE_ID = os.environ["DATA_SOURCE_ID"]
MOODLE_TOKEN_SECRET_NAME = os.environ["MOODLE_TOKEN_SECRET_NAME"]

# Global temporary directory for file downloads
TEMP_DIR = tempfile.mkdtemp()


@dataclass
class FileInfo:
    """Data class to represent file information from Moodle.

    Attributes:
        file_url: The URL to download the file from Moodle
        file_name: The name of the file
        mime_type: The MIME type of the file
    """

    file_url: str
    file_name: str
    mime_type: str

    @property
    def file_path(self) -> str:
        """Calculate safe file path in global temporary directory.

        Sanitizes filename to prevent path traversal attacks (CWE-22).

        Returns:
            str: A sanitized file path in the temporary directory
        """
        # Extract basename and sanitize
        safe_filename = os.path.basename(self.file_name)
        # Remove any remaining path separators and null bytes
        safe_filename = safe_filename.replace(os.sep, "_").replace(os.altsep or "", "_")
        safe_filename = safe_filename.replace("\0", "")
        # Whitelist allowed characters (alphanumeric, dots, underscores, hyphens)
        safe_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", safe_filename)
        # Ensure it's not empty or hidden file
        if not safe_filename or safe_filename.startswith("."):
            safe_filename = f"file_{secrets.token_hex(8)}"
        return os.path.join(TEMP_DIR, safe_filename)


def get_moodle_token() -> str:
    """Retrieve Moodle API token from AWS Secrets Manager.

    Returns:
        str: The Moodle API token string

    Raises:
        ValueError: If secret cannot be retrieved or is invalid
    """
    from botocore.exceptions import ClientError

    try:
        response = parameters.get_secret(name=MOODLE_TOKEN_SECRET_NAME)
        return response
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'ResourceNotFoundException':
            logger.error(f"Secret not found: {MOODLE_TOKEN_SECRET_NAME}")
            raise ValueError("Moodle token secret not found") from e
        elif error_code == 'AccessDeniedException':
            logger.error(f"Access denied to secret: {MOODLE_TOKEN_SECRET_NAME}")
            raise ValueError("Insufficient permissions to access secret") from e
        elif error_code == 'DecryptionFailure':
            logger.error(f"Failed to decrypt secret: {MOODLE_TOKEN_SECRET_NAME}")
            raise ValueError("Failed to decrypt secret") from e
        else:
            logger.error(f"AWS error retrieving secret [{error_code}]: {str(e)}")
            raise ValueError(f"Failed to retrieve Moodle token: {error_code}") from e
    except Exception as e:
        logger.error(f"Unexpected error retrieving Moodle token: {str(e)}")
        raise ValueError("Failed to retrieve Moodle token") from e


def get_course_info(course_id: int) -> List[Dict[str, Any]]:
    """Fetch course content information from Moodle API.

    Args:
        course_id: The Moodle course ID

    Returns:
        List[Dict[str, Any]]: List of course sections with modules and content

    Raises:
        requests.Timeout: If request times out
        requests.HTTPError: If HTTP error occurs
        requests.RequestException: If network error occurs
        ValueError: If Moodle returns an API error or invalid JSON
    """
    try:
        # Call Moodle web service to get course contents
        response = requests.get(
            f"{MOODLE_URL}/webservice/rest/server.php",
            params={
                "wstoken": get_moodle_token(),
                "wsfunction": "core_course_get_contents",
                "moodlewsrestformat": "json",
                "courseid": course_id,
            },
            timeout=10,
        )

        response.raise_for_status()

    except requests.Timeout as e:
        logger.error(f"Timeout fetching course {course_id}: {str(e)}")
        raise
    except requests.HTTPError as e:
        logger.error(
            f"HTTP error fetching course {course_id}: {e.response.status_code} - {str(e)}"
        )
        raise
    except requests.RequestException as e:
        logger.error(f"Network error fetching course {course_id}: {str(e)}")
        raise

    # Parse JSON response
    try:
        data = response.json()
    except requests.exceptions.JSONDecodeError as e:
        logger.warning(f"Invalid JSON response for course {course_id}: {str(e)}")
        raise ValueError(f"Invalid JSON from Moodle API: {str(e)}") from e

    # Check for Moodle webservice exceptions in response
    if isinstance(data, dict) and "exception" in data:
        error_msg = data.get("message", "Unknown Moodle error")
        error_code = data.get("errorcode", "unknown")
        logger.warning(
            f"Moodle API error for course {course_id} [{error_code}]: {error_msg}"
        )
        raise ValueError(f"Moodle API error [{error_code}]: {error_msg}")

    return data


def get_module_info(
    section_id: int, course_info: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Find specific module information by ID from course data.

    Args:
        section_id: The module ID to search for
        course_info: Course data from Moodle API containing sections and modules

    Returns:
        Optional[Dict[str, Any]]: Module information dict if found, None otherwise
    """
    # Build a map of all modules by ID for quick lookup
    module_map = {}
    for section in course_info:
        for module in section.get("modules", []):
            module_map[module["id"]] = module
    return module_map.get(section_id)


def get_file_infos(module_info: Dict[str, Any]) -> List[FileInfo]:
    """Extract file information from module content.

    Args:
        module_info: Module data containing content items

    Returns:
        List[FileInfo]: List of FileInfo objects for files in the module
    """
    file_infos = []

    # Iterate through module contents and extract file information
    for content in module_info.get("contents", []):
        if content.get("type") == "file":
            try:
                file_info = FileInfo(
                    file_url=content["fileurl"],
                    file_name=content["filename"],
                    mime_type=content["mimetype"],
                )
                file_infos.append(file_info)
            except KeyError as e:
                logger.warning(f"Skipping file with missing field {str(e)}: {content}")

    return file_infos


def index_file(file_info: FileInfo) -> Dict[str, Any]:
    """Index a single file into AWS Bedrock Knowledge Base.

    Args:
        file_info: File metadata from Moodle with calculated file path

    Returns:
        Dict[str, Any]: Bedrock ingestion response dict

    Raises:
        IOError: If file cannot be read
        botocore.exceptions.ClientError: If Bedrock API call fails
    """
    # Read file content as bytes
    with open(file_info.file_path, "rb") as f:
        file_content = f.read()

    # Ingest document into Bedrock Knowledge Base
    response = bedrock_agent_client.ingest_knowledge_base_documents(
        knowledgeBaseId=KNOWLEDGE_BASE_ID,
        dataSourceId=DATA_SOURCE_ID,
        documents=[
            {
                "content": {
                    "custom": {
                        "customDocumentIdentifier": {"id": file_info.file_url},
                        "inlineContent": {
                            "byteContent": {
                                "data": file_content,
                                "mimeType": file_info.mime_type,
                            },
                            "type": "BYTE",
                        },
                        "sourceType": "IN_LINE",
                    },
                    "dataSourceType": "CUSTOM",
                }
            }
        ],
    )

    logger.info(f"Successful ingestion: {json.dumps(response, default=str)}")
    return response


def index_files(module_info: Dict[str, Any]) -> None:
    """Download and index all files from a Moodle module.

    Args:
        module_info: Module data containing file information

    Raises:
        requests.RequestException: If file download fails
        IOError: If file write fails
        botocore.exceptions.ClientError: If Bedrock indexing fails
        Exception: If other file processing fails
    """
    # Extract file information from module
    file_infos = get_file_infos(module_info)

    # Process each file in the module
    for file_info in file_infos:
        try:
            # Download file from Moodle with authentication token
            response = requests.get(
                f"{file_info.file_url}&token={get_moodle_token()}", timeout=30
            )
            response.raise_for_status()

            # Save file to calculated path (already sanitized in property)
            with open(file_info.file_path, "wb") as f:
                f.write(response.content)

            # Index the file into Bedrock Knowledge Base
            index_file(file_info)
            logger.info("Successfully indexed: %s", file_info.file_url)
        except requests.RequestException as e:
            logger.error(f"Error downloading file {file_info.file_url}: {str(e)}")
        except IOError as e:
            logger.error(f"Error writing file {file_info.file_path}: {str(e)}")
        except bedrock_agent_client.exceptions.ClientError as e:
            logger.error(f"Bedrock error indexing {file_info.file_url}: {str(e)}")


@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
@event_source(data_class=EventBridgeEvent)  # pylint: disable:no-value-for-parameter
def lambda_handler(
    event: EventBridgeEvent, context: LambdaContext
) -> None:  # pylint: disable=unused-argument
    """Lambda handler to process Moodle file events and index them in Bedrock.

    Triggered by EventBridge events when files are added/updated in Moodle.
    Downloads the files and indexes them into AWS Bedrock Knowledge Base.

    Args:
        event: EventBridge event containing course and module IDs in detail
        context: Lambda runtime context (unused)

    Raises:
        ValueError: If required event fields are missing
        Exception: If file processing fails
    """
    try:
        # Extract event details
        course_id: int = event.detail["courseid"]
        module_id: int = event.detail["objectid"]
    except KeyError as e:
        logger.warning(f"Missing required event field: {str(e)}")
        raise ValueError(f"Invalid event structure: missing {str(e)}") from e

    try:
        # Fetch course information from Moodle
        course_info: List[Dict[str, Any]] = get_course_info(course_id)
        # Find the specific module that triggered the event
        module_info: Optional[Dict[str, Any]] = get_module_info(module_id, course_info)

        # Process files if module exists
        if module_info:
            index_files(module_info)
    except Exception as e:
        logger.warning(f"Failed to process file indexing: {str(e)}")
        raise

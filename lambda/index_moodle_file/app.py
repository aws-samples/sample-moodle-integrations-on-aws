"""Lambda function for indexing and deleting Moodle files in AWS Bedrock Knowledge Base.

This module processes EventBridge events triggered when files are added, updated,
or deleted in Moodle courses. It handles both indexing new/updated files and
removing deleted files from the AWS Bedrock Knowledge Base.

The workflow for indexing:
1. Receives EventBridge event with course ID, module ID, and context ID
2. Fetches course content information from Moodle API
3. Locates the specific module that triggered the event
4. Downloads any files in that module from Moodle
5. Indexes the files with course_id and contextid metadata
6. Handles errors and retries appropriately

The workflow for deletion:
1. Receives EventBridge event with context ID
2. Queries Knowledge Base for documents with matching contextid metadata
3. Deletes all matching documents from Knowledge Base

Required environment variables:
- MOODLE_DNS: DNS name of Moodle server
- KNOWLEDGE_BASE_ID: ID of AWS Bedrock Knowledge Base
- DATA_SOURCE_ID: ID of data source in Knowledge Base
- MOODLE_TOKEN_SECRET_NAME: Name of secret containing Moodle API token
- KB_STAGING_BUCKET: S3 bucket for staging large files (optional)
- AWS_ACCOUNT_ID: AWS account ID for S3 staging bucket ownership
"""

import requests
import json
import os
import tempfile
import time
import random
import boto3
import re
import secrets
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from botocore.exceptions import ClientError

from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities import parameters
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.data_classes import EventBridgeEvent, event_source

from pptx_extractor import extract_text_from_pptx


logger = Logger()
tracer = Tracer()


bedrock_agent_client = boto3.client("bedrock-agent")
bedrock_agent_runtime_client = boto3.client("bedrock-agent-runtime")
s3_client = boto3.client("s3")

MOODLE_URL = f"https://{os.environ['MOODLE_DNS']}"
KNOWLEDGE_BASE_ID = os.environ["KNOWLEDGE_BASE_ID"]
DATA_SOURCE_ID = os.environ["DATA_SOURCE_ID"]
MOODLE_TOKEN_SECRET_NAME = os.environ["MOODLE_TOKEN_SECRET_NAME"]
KB_STAGING_BUCKET = os.environ.get("KB_STAGING_BUCKET", "")

# Maximum inline content size for IngestKnowledgeBaseDocuments API (6MB limit).
# Use 4MB threshold because base64 encoding inflates the payload by ~33%.
MAX_INLINE_BYTES = 4 * 1024 * 1024

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


def index_file(file_info: FileInfo, course_id: str, context_id: str) -> Dict[str, Any]:
    """Index a single file into AWS Bedrock Knowledge Base.

    For PPTX files, extracts text content before indexing since Bedrock KB
    doesn't natively support PowerPoint format.

    Args:
        file_info: File metadata from Moodle with calculated file path
        course_id: The Moodle course ID to add as metadata for filtering
        context_id: The Moodle context ID to add as metadata for deletion

    Returns:
        Dict[str, Any]: Bedrock ingestion response dict

    Raises:
        IOError: If file cannot be read
        botocore.exceptions.ClientError: If Bedrock API call fails
    """
    # Check if file is PPTX and needs text extraction
    is_pptx = file_info.mime_type in [
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-powerpoint"
    ]

    if is_pptx:
        # Extract text from PPTX and convert to plain text
        try:
            extracted_text = extract_text_from_pptx(file_info.file_path)
            file_content = extracted_text.encode('utf-8')
            mime_type = "text/plain"
            logger.info(f"Extracted {len(extracted_text)} characters from PPTX: {file_info.file_name}")
        except Exception as e:
            logger.error(f"Failed to extract text from PPTX {file_info.file_name}: {str(e)}")
            raise
    else:
        # Read file content as bytes for non-PPTX files
        with open(file_info.file_path, "rb") as f:
            file_content = f.read()
        mime_type = file_info.mime_type

    # Shared metadata for both inline and S3 ingestion paths
    metadata = {
        "type": "IN_LINE_ATTRIBUTE",
        "inlineAttributes": [
            {
                "key": "course_id",
                "value": {"type": "STRING", "stringValue": course_id},
            },
            {
                "key": "contextid",
                "value": {"type": "STRING", "stringValue": context_id},
            },
        ],
    }

    # Use S3 staging for large files that exceed the inline API limit
    if len(file_content) > MAX_INLINE_BYTES and KB_STAGING_BUCKET:
        s3_key = f"{context_id}/{file_info.file_name}"
        logger.info(
            f"File {file_info.file_name} is {len(file_content)} bytes, "
            f"staging to s3://{KB_STAGING_BUCKET}/{s3_key}"
        )
        s3_client.put_object(
            Bucket=KB_STAGING_BUCKET,
            Key=s3_key,
            Body=file_content,
            ContentType=mime_type,
        )
        content_config = {
            "custom": {
                "customDocumentIdentifier": {"id": file_info.file_url},
                "s3Location": {
                    "bucketOwnerAccountId": os.environ["AWS_ACCOUNT_ID"],
                    "uri": f"s3://{KB_STAGING_BUCKET}/{s3_key}",
                },
                "sourceType": "S3_LOCATION",
            },
            "dataSourceType": "CUSTOM",
        }
    else:
        content_config = {
            "custom": {
                "customDocumentIdentifier": {"id": file_info.file_url},
                "inlineContent": {
                    "byteContent": {
                        "data": file_content,
                        "mimeType": mime_type,
                    },
                    "type": "BYTE",
                },
                "sourceType": "IN_LINE",
            },
            "dataSourceType": "CUSTOM",
        }

    response = bedrock_agent_client.ingest_knowledge_base_documents(
        knowledgeBaseId=KNOWLEDGE_BASE_ID,
        dataSourceId=DATA_SOURCE_ID,
        documents=[{"content": content_config, "metadata": metadata}],
    )

    logger.info(f"Successful ingestion with course_id={course_id}, contextid={context_id}: {json.dumps(response, default=str)}")
    return response


def index_files(module_info: Dict[str, Any], course_id: str, context_id: str) -> None:
    """Download and index all files from a Moodle module.

    Args:
        module_info: Module data containing file information
        course_id: The Moodle course ID to add as metadata for filtering
        context_id: The Moodle context ID to add as metadata for deletion

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

            # Index the file into Bedrock Knowledge Base with course_id and contextid
            index_file(file_info, course_id, context_id)
            logger.info("Successfully indexed: %s", file_info.file_url)
        except requests.RequestException as e:
            logger.error(f"Error downloading file {file_info.file_url}: {str(e)}")
        except IOError as e:
            logger.error(f"Error writing file {file_info.file_path}: {str(e)}")
        except bedrock_agent_client.exceptions.ClientError as e:
            logger.error(f"Bedrock error indexing {file_info.file_url}: {str(e)}")


def delete_documents_by_context(context_id: str) -> None:
    """Delete all documents associated with a Moodle context from Knowledge Base.

    Uses the context ID metadata to identify and delete all documents from
    a deleted module. This is a two-step process:
    1. Retrieve documents with matching contextid metadata
    2. Delete those documents by their identifiers

    Args:
        context_id: The Moodle context ID from the deletion event

    Raises:
        botocore.exceptions.ClientError: If Bedrock API calls fail
    """
    logger.info(f"Deleting documents with contextid={context_id}")

    try:
        # Step 1: Retrieve documents with matching contextid
        retrieve_response = bedrock_agent_runtime_client.retrieve(
            knowledgeBaseId=KNOWLEDGE_BASE_ID,
            retrievalQuery={
                "text": "*"  # Match all documents
            },
            retrievalConfiguration={
                "vectorSearchConfiguration": {
                    "numberOfResults": 100,
                    "filter": {
                        "equals": {
                            "key": "contextid",
                            "value": context_id
                        }
                    }
                }
            }
        )

        # Extract document identifiers from results
        results = retrieve_response.get("retrievalResults", [])

        if not results:
            logger.info(f"No documents found with contextid={context_id}")
            return

        # Build list of document identifiers to delete
        document_identifiers = []
        for result in results:
            location = result.get("location", {})
            if location.get("type") == "CUSTOM":
                custom_id = location.get("customDocumentLocation", {}).get("id")
                if custom_id:
                    document_identifiers.append({
                        "custom": {
                            "id": custom_id
                        },
                        "dataSourceType": "CUSTOM"
                    })

        if not document_identifiers:
            logger.warning(f"Found {len(results)} results but no valid document identifiers")
            return

        # Deduplicate by custom ID
        seen_ids = set()
        unique_identifiers = []
        for doc_id in document_identifiers:
            custom_id = doc_id.get("custom", {}).get("id")
            if custom_id and custom_id not in seen_ids:
                seen_ids.add(custom_id)
                unique_identifiers.append(doc_id)
        document_identifiers = unique_identifiers

        logger.info(f"Found {len(document_identifiers)} unique documents to delete")

        # Step 2: Delete the documents in batches of 25 (API limit)
        batch_size = 25
        for i in range(0, len(document_identifiers), batch_size):
            batch = document_identifiers[i:i + batch_size]
            logger.info(f"Deleting batch {i // batch_size + 1} ({len(batch)} documents)")
            delete_response = bedrock_agent_client.delete_knowledge_base_documents(
                knowledgeBaseId=KNOWLEDGE_BASE_ID,
                dataSourceId=DATA_SOURCE_ID,
                documentIdentifiers=batch
            )
            logger.info(f"Batch delete response: {json.dumps(delete_response, default=str)}")

        logger.info(f"Successfully deleted all documents with contextid={context_id}")

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        logger.error(f"Failed to delete documents with contextid={context_id} [{error_code}]: {str(e)}")

        if error_code in ['ValidationException', 'InvalidRequestException']:
            logger.warning(
                f"Metadata filtering may not be supported. "
                f"Manual cleanup required for contextid={context_id}. "
                f"Documents may need to be deleted individually."
            )
        raise


@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
@event_source(data_class=EventBridgeEvent)  # pylint: disable:no-value-for-parameter
def lambda_handler(
    event: EventBridgeEvent, context: LambdaContext
) -> None:  # pylint: disable=unused-argument
    """Lambda handler to process Moodle file events and index or delete them in Bedrock.

    Triggered by EventBridge events when files are added/updated/deleted in Moodle.
    Routes to indexing or deletion based on the event action.

    Args:
        event: EventBridge event containing course, module, and context IDs in detail
        context: Lambda runtime context (unused)

    Raises:
        ValueError: If required event fields are missing
        Exception: If file processing fails
    """
    try:
        # Extract event details — Moodle sends IDs as strings
        course_id: int = int(event.detail["courseid"])
        module_id: int = int(event.detail["objectid"])
        context_id: int = int(event.detail["contextid"])
        action: str = event.detail.get("action", "created")
    except KeyError as e:
        logger.warning(f"Missing required event field: {str(e)}")
        raise ValueError(f"Invalid event structure: missing {str(e)}") from e

    try:
        if action == "deleted":
            # Handle deletion - use contextid to find and delete documents
            logger.info(f"Processing deletion for contextid={context_id}, module={module_id}, course={course_id}")
            delete_documents_by_context(str(context_id))
        else:
            # Handle creation/update - fetch module info and index files
            logger.info(f"Processing indexing for module={module_id}, course={course_id}, contextid={context_id}")

            # Retry lookup — newly created modules may not be immediately
            # visible via the Moodle web service API.
            module_info: Optional[Dict[str, Any]] = None
            max_retries = 5
            for attempt in range(max_retries):
                course_info: List[Dict[str, Any]] = get_course_info(course_id)
                # Log available module IDs for debugging
                all_module_ids = [
                    m["id"]
                    for section in course_info
                    for m in section.get("modules", [])
                ]
                logger.debug(f"Course {course_id} has {len(all_module_ids)} modules: {all_module_ids}")
                module_info = get_module_info(module_id, course_info)
                if module_info:
                    break
                if attempt == max_retries - 1:
                    break  # Don't sleep after last attempt
                base_delay = min(2 ** attempt, 4)  # Cap at 4s to stay within Lambda timeout
                jitter = random.uniform(0, base_delay * 0.5)
                delay = base_delay + jitter
                logger.info(f"Module {module_id} not found on attempt {attempt + 1}/{max_retries}, retrying in {delay:.1f}s")
                time.sleep(delay)

            # Process files if module exists
            if module_info:
                index_files(module_info, str(course_id), str(context_id))
            else:
                logger.warning(f"Module {module_id} not found in course {course_id} after {max_retries} attempts")
    except Exception as e:
        logger.warning(f"Failed to process file event: {str(e)}")
        raise

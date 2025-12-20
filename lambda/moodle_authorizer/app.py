"""API Gateway Lambda authorizer for Moodle integration.

This module provides token-based authorization for API Gateway requests,
validating Moodle web service tokens. It validates tokens by making test API calls
to Moodle and generates IAM policies for API Gateway based on the validation result.
"""

import os
import requests
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext


logger = Logger()
tracer = Tracer()


@logger.inject_lambda_context
@tracer.capture_lambda_handler
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """Lambda authorizer handler for API Gateway TOKEN authorization.

    Validates Moodle web service tokens provided in the Authorization header.
    Uses core_webservice_get_site_info for efficient token validation.

    Args:
        event: API Gateway authorizer event containing authorizationToken
        context: Lambda runtime context

    Returns:
        dict: IAM policy document allowing or denying API access
    """
    try:
        # TOKEN authorizer receives token directly in authorizationToken
        token = event.get("authorizationToken", "").replace("Bearer ", "")

        if not token:
            logger.warning("No token provided")
            return generate_policy("user", "Deny", event["methodArn"])

        moodle_url = os.environ.get("MOODLE_URL")
        if not moodle_url:
            logger.error("MOODLE_URL environment variable not set")
            return generate_policy("user", "Deny", event["methodArn"])

        username = validate_moodle_token(token, moodle_url)
        if username:
            return generate_policy(username, "Allow", event["methodArn"])

        logger.warning("Token validation failed")
        return generate_policy("user", "Deny", event["methodArn"])

    except Exception:
        logger.exception("Authorization error")
        return generate_policy("user", "Deny", event["methodArn"])


@tracer.capture_method
def validate_moodle_token(token: str, moodle_url: str) -> str:
    """Validate Moodle web service token using core_webservice_get_site_info.

    This is the standard Moodle approach for token validation. It validates
    the token and retrieves user information in a single API call.

    Args:
        token: Moodle web service token to validate
        moodle_url: Base URL of the Moodle instance

    Returns:
        str: Username of token owner if validation succeeds, None if validation fails
    """
    try:
        data = {
            "wstoken": token,
            "wsfunction": "core_webservice_get_site_info",
            "moodlewsrestformat": "json",
        }

        url = f"{moodle_url}/webservice/rest/server.php"
        logger.debug(
            "Validating Moodle token",
            extra={"url": url, "token_length": len(token)},
        )

        response = requests.post(url, data=data, timeout=10)
        response.raise_for_status()
        result = response.json()

        logger.debug(
            "Moodle validation response",
            extra={
                "status_code": response.status_code,
                "has_error": "exception" in result or "error" in result,
            },
        )

        # Check for error responses
        if isinstance(result, dict) and ("exception" in result or "error" in result):
            error_code = result.get("errorcode", "unknown")
            error_msg = result.get("message", "Unknown error")
            logger.warning(
                "Token validation failed",
                extra={"error_code": error_code, "error_message": error_msg},
            )
            return None

        # Successful validation - extract username
        username = result.get("username")
        if username:
            logger.info(
                "Token validation successful",
                extra={
                    "username": username,
                    "userid": result.get("userid"),
                    "firstname": result.get("firstname"),
                },
            )
            return username

        logger.warning("Token validation returned no username")
        return None

    except requests.RequestException as e:
        logger.error(f"Network error during token validation: {str(e)}")
        return None
    except Exception:
        logger.exception("Unexpected error during token validation")
        return None


def generate_policy(principal_id, effect, resource):
    """Generate IAM policy document for API Gateway.

    Creates a policy document that allows or denies access to the API Gateway resource.
    The principal ID is set to either the Moodle username for successful validations,
    or 'user' for failed validations.

    Args:
        principal_id: User identifier for the policy (Moodle username or 'user')
        effect: 'Allow' for valid tokens, 'Deny' for invalid tokens
        resource: API Gateway resource ARN to control access to

    Returns:
        dict: IAM policy document with principalId and policyDocument containing
              the execute-api:Invoke permission
    """
    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        },
    }

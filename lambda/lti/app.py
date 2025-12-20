"""LTI 1.3 authentication handler for Moodle integration.

This module implements LTI 1.3 OIDC login flow and launch handling for integrating
Moodle with external tools. It manages authentication, token validation, and user
session creation using JWT tokens stored in DynamoDB.
"""
import json
import os
import base64
import urllib.parse
import time
import uuid
import boto3
import jwt

from typing import Dict, Any
from datetime import datetime, timedelta, timezone

from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.event_handler import (
    APIGatewayRestResolver,
    Response,
)
from aws_lambda_powertools.event_handler.exceptions import BadRequestError
from aws_lambda_powertools.utilities import parameters
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.logging import correlation_paths

# Initialize Powertools
logger = Logger()
tracer = Tracer()
app = APIGatewayRestResolver()

# Initialize DynamoDB
dynamodb = boto3.resource('dynamodb')

# Constants
TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
STATE_NONCE_TTL_SECONDS = 600  # 10 minutes
LTI_VERSION = "1.3.0"
LTI_CLAIM_PREFIX = "https://purl.imsglobal.org/spec/lti/claim/"
TOKEN_PREFIX = "token_"  # nosec B105 - Not a password, just a DynamoDB key prefix
TOKEN_PLACEHOLDER = "used"  # nosec B105 - Not a password, just a placeholder value

# Cache environment variables at module level for performance
WEBSITE_URL = os.environ.get("WEBSITE_URL", "")
STATE_TABLE_NAME = os.environ.get("STATE_TABLE_NAME", "")
JWT_SECRET_NAME = os.environ.get("JWT_SECRET_NAME")
CLIENT_ID_PARAM = os.environ.get("CLIENT_ID_PARAM")
REDIRECT_URL_PARAM = os.environ.get("REDIRECT_URL_PARAM")
OIDC_AUTH_URL = os.environ.get("OIDC_AUTH_URL")
MOODLE_URL = os.environ.get("MOODLE_URL", "")

# Validate required environment variables
required_vars = {
    "JWT_SECRET_NAME": JWT_SECRET_NAME,
    "CLIENT_ID_PARAM": CLIENT_ID_PARAM,
    "REDIRECT_URL_PARAM": REDIRECT_URL_PARAM,
    "OIDC_AUTH_URL": OIDC_AUTH_URL
}
for var_name, var_value in required_vars.items():
    if not var_value:
        raise ValueError(f"Required environment variable {var_name} is not set")

# Cache DynamoDB table instance
_dynamodb_table = None


def get_dynamodb_table():
    """Get cached DynamoDB table instance.
    
    Returns:
        Table: Boto3 DynamoDB Table resource for state/token storage
    """
    global _dynamodb_table
    if _dynamodb_table is None:
        _dynamodb_table = dynamodb.Table(STATE_TABLE_NAME)
    return _dynamodb_table


def get_jwt_secret() -> str:
    """Fetch and parse JWT secret from Secrets Manager.
    
    Returns:
        str: JWT signing secret
        
    Raises:
        ValueError: If secret cannot be retrieved or is invalid
    """
    try:
        jwt_secret_json = parameters.get_secret(JWT_SECRET_NAME, max_age=300)
        secret_data = json.loads(jwt_secret_json)
        secret = secret_data.get('secret')
        if not secret:
            raise ValueError("JWT secret is empty or missing 'secret' key")
        return secret
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in JWT secret: {str(e)}")
        raise ValueError("JWT secret contains invalid JSON") from e
    except Exception as e:
        logger.error(f"Failed to retrieve JWT secret: {str(e)}")
        raise ValueError("Failed to retrieve JWT secret") from e


def extract_auth_token(headers: dict) -> str:
    """Extract Bearer token from Authorization header.
    
    Args:
        headers: Request headers dictionary
        
    Returns:
        str: Extracted token
        
    Raises:
        BadRequestError: If token is missing or invalid format
    """
    auth_header = headers.get('authorization', '') or headers.get('Authorization', '')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise BadRequestError("No authentication token found")
    return auth_header.replace('Bearer ', '')


def extract_lti_user_info(payload: dict) -> dict:
    """Extract user information from LTI token payload.
    
    Args:
        payload: Decoded LTI JWT payload
        
    Returns:
        dict: User information with user_id, username, context, and context_title
    """
    user_id = payload.get("sub")
    custom_claims = payload.get(f"{LTI_CLAIM_PREFIX}custom", {})
    context = payload.get(f"{LTI_CLAIM_PREFIX}context", {})
    
    return {
        'user_id': user_id,
        'username': custom_claims.get("_username"),
        'context': context,
        'context_title': context.get("title"),
    }

@app.post("/lti/login")
@tracer.capture_method
def oidc_login():
    """Handle OIDC login initiation for LTI 1.3.
    
    Processes the initial login request from Moodle, generates state and nonce
    for CSRF protection, stores them in DynamoDB, and redirects to Moodle's
    OIDC authentication endpoint.
    
    Returns:
        Response: HTTP 302 redirect to Moodle OIDC endpoint
        
    Raises:
        BadRequestError: If required OIDC parameters are missing
    """
    try: 
        # Parse form body (x-www-form-urlencoded)
        form_data = urllib.parse.parse_qs(app.current_event.body)

        login_hint = form_data.get("login_hint", [None])[0]
        lti_message_hint = form_data.get("lti_message_hint", [None])[0]

        if not login_hint or not lti_message_hint:
            raise BadRequestError("Missing required OIDC parameters: login_hint or lti_message_hint")

        client_id = parameters.get_parameter(CLIENT_ID_PARAM, max_age=60)
        redirect_url = parameters.get_parameter(REDIRECT_URL_PARAM, max_age=60)

        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())

        # Store state and nonce in DynamoDB for CSRF protection
        table = get_dynamodb_table()
        table.put_item(
            Item={
                'state': state,
                'nonce': nonce,
                'ttl': int(time.time()) + STATE_NONCE_TTL_SECONDS
            }
        )
        logger.debug(f"Stored state/nonce for OIDC flow", extra={"state": state})

        url = (
            f"{OIDC_AUTH_URL}?"
            f"scope=openid&"
            f"response_type=id_token&"
            f"client_id={client_id}&"
            f"redirect_uri={urllib.parse.quote(redirect_url)}&"
            f"login_hint={urllib.parse.quote(login_hint)}&"
            f"state={state}&"
            f"nonce={nonce}&"
            f"response_mode=form_post&"
            f"prompt=none&"
            f"lti_message_hint={urllib.parse.quote(lti_message_hint)}"
        )

        logger.debug(f"Redirecting to: {url}")

        return Response(
            status_code=302,
            headers={"Location": url},
            body=""
        )
    except BadRequestError:
        raise

def verify_lti_token(id_token: str, moodle_url: str, client_id: str, expected_launch_url: str = None) -> dict:
    """Verify LTI 1.3 ID token signature and claims.
    
    Validates the JWT token from Moodle by:
    - Fetching public keys from Moodle's JWKS endpoint
    - Verifying the token signature
    - Validating required LTI claims
    - Checking issuer and LTI version
    
    Args:
        id_token: JWT token from Moodle
        moodle_url: Base URL of the Moodle instance
        client_id: OAuth client ID for audience validation
        
    Returns:
        dict: Decoded and validated JWT payload
        
    Raises:
        BadRequestError: If token is invalid, expired, or missing required claims
    """
    try:
        # Fetch Moodle's public keys from JWKS endpoint
        jwks_url = f"{moodle_url}/mod/lti/certs.php"
        jwks_client = jwt.PyJWKClient(jwks_url, cache_keys=True)
        
        # Get signing key from token header
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        
        # Verify signature and decode
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            options={"verify_exp": True, "verify_aud": True}
        )
        
        # Validate required LTI claims
        required_claims = [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nonce",
            f"{LTI_CLAIM_PREFIX}message_type",
            f"{LTI_CLAIM_PREFIX}version",
            f"{LTI_CLAIM_PREFIX}deployment_id",
            f"{LTI_CLAIM_PREFIX}target_link_uri",
            f"{LTI_CLAIM_PREFIX}resource_link"
        ]
        
        for claim in required_claims:
            if claim not in payload:
                raise BadRequestError(f"Missing required claim: {claim}")
        
        # Validate resource_link has required id property
        resource_link = payload.get(f"{LTI_CLAIM_PREFIX}resource_link", {})
        if not resource_link.get("id"):
            raise BadRequestError("Missing required resource_link.id property")
        
        # Validate issuer matches Moodle URL
        if not payload["iss"].startswith(moodle_url):
            raise BadRequestError(f"Invalid issuer: {payload['iss']}")
        
        # Validate LTI version
        if payload.get(f"{LTI_CLAIM_PREFIX}version") != LTI_VERSION:
            raise BadRequestError("Unsupported LTI version")
        
        # Validate message type
        message_type = payload.get(f"{LTI_CLAIM_PREFIX}message_type")
        if message_type != "LtiResourceLinkRequest":
            raise BadRequestError(f"Unsupported message type: {message_type}")
        
        # Validate target_link_uri matches expected launch URL
        if expected_launch_url:
            target_link_uri = payload.get(f"{LTI_CLAIM_PREFIX}target_link_uri")
            if not target_link_uri.startswith(expected_launch_url):
                raise BadRequestError("Invalid target_link_uri")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.warning("ID token expired")
        raise BadRequestError("ID token has expired")
    except jwt.InvalidAudienceError:
        logger.warning("Invalid audience in ID token")
        raise BadRequestError("Invalid token audience")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid ID token: {str(e)}")
        raise BadRequestError(f"Invalid ID token: {str(e)}")

@app.post("/lti/launch")
@tracer.capture_method
def lti_launch():
    """Handle LTI launch requests from Moodle.
    
    Processes the LTI launch by:
    - Validating the state parameter against DynamoDB
    - Verifying the ID token signature and claims
    - Validating the nonce to prevent replay attacks
    - Extracting user information from the token
    - Generating a session JWT (1 hour expiry)
    - Storing token ID in DynamoDB for one-time validation
    - Redirecting to the application with the token
    
    Returns:
        Response: HTTP 302 redirect to application with JWT token in URL fragment
        
    Raises:
        BadRequestError: If validation fails or required parameters are missing
        KeyError: If LTI payload is missing expected fields
        ValueError: If data cannot be parsed correctly
        TypeError: If data types are incorrect
    """
    try:
        # Log the request
        logger.debug("Received LTI 1.3 launch")

        body = app.current_event.body
        # Check if body is base64 encoded
        is_base64 = app.current_event.get("isBase64Encoded", False)
        if is_base64 and body:
            body = base64.b64decode(body).decode("utf-8")

        params = urllib.parse.parse_qs(body)
        id_token = params.get("id_token", [None])[0]
        state = params.get("state", [None])[0]

        if not id_token:
            raise BadRequestError("Missing id_token")
        if not state:
            raise BadRequestError("Missing state parameter")

        # Validate state and retrieve nonce from DynamoDB
        table = get_dynamodb_table()
        response = table.get_item(Key={'state': state})
        
        if 'Item' not in response:
            logger.warning("Invalid or expired state", extra={"state": state})
            raise BadRequestError("Invalid or expired state - possible CSRF attack")
        
        stored_nonce = response['Item']['nonce']
        
        # Delete state immediately (one-time use)
        table.delete_item(Key={'state': state})
        logger.debug("State validated and consumed", extra={"state": state})

        # Get Moodle URL and client ID for verification
        moodle_url = MOODLE_URL
        
        client_id = parameters.get_parameter(CLIENT_ID_PARAM, max_age=60)
        redirect_url = parameters.get_parameter(REDIRECT_URL_PARAM, max_age=60)
        
        # Verify ID token signature and claims
        payload = verify_lti_token(id_token, moodle_url, client_id, redirect_url)
        
        # Validate nonce matches stored value
        if payload.get('nonce') != stored_nonce:
            logger.error("Nonce mismatch", extra={
                "expected": stored_nonce,
                "received": payload.get('nonce')
            })
            raise BadRequestError("Nonce mismatch - possible CSRF attack")
        
        logger.debug("Verified LTI token with valid nonce")

        # Extract user information
        user_info = extract_lti_user_info(payload)

        logger.info("User authenticated successfully", extra={
            'user_id': user_info['user_id'],
            'username': user_info['username'],
            'context_title': user_info['context_title']
        })
        
        # Generate signed JWT session token
        jwt_secret = get_jwt_secret()
        token_id = str(uuid.uuid4())
        token = jwt.encode(
            {
                **user_info,
                'exp': datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRY_SECONDS),
                'iat': datetime.now(timezone.utc),
                'jti': token_id
            },
            jwt_secret,
            algorithm='HS256'
        )
        
        # Store token ID in DynamoDB with matching TTL for one-time use validation
        table = get_dynamodb_table()
        table.put_item(
            Item={
                'state': f"{TOKEN_PREFIX}{token_id}",
                'nonce': TOKEN_PLACEHOLDER,
                'ttl': int(time.time()) + TOKEN_EXPIRY_SECONDS
            }
        )
        
        logger.debug("Generated session token", extra={"token_id": token_id})

        # Redirect with token in URL fragment (not sent to server)
        return Response(
            status_code=302,
            headers={"Location": f"{WEBSITE_URL}#token={token}"},
            body=""
        )  
        
    except BadRequestError:
        logger.warning("Bad request in LTI launch")
        raise
    except (KeyError, ValueError, TypeError) as e:
        logger.error(f"Invalid LTI launch data: {str(e)}")
        raise BadRequestError(f"Invalid LTI launch data: {str(e)}")
    except Exception as e:
        logger.exception("Unexpected error processing LTI launch request")
        raise

@app.get("/api/user/info")
@tracer.capture_method
def get_user_info():
    """Return user info from JWT token (one-time use).
    
    Validates the JWT token from the Authorization header, ensures it's a
    one-time use token by checking DynamoDB, and returns the user information.
    The token is deleted from DynamoDB after validation to prevent reuse.
    
    Returns:
        dict: User information with keys:
            - user_id: User identifier from LTI
            - username: Username from LTI custom claims
            - context_title: Course/context title
            - context: Full context object from LTI
        
    Raises:
        BadRequestError: If token is missing, invalid, expired, already used, or missing jti claim
        jwt.ExpiredSignatureError: If JWT has expired (caught and re-raised as BadRequestError)
        jwt.InvalidTokenError: If JWT signature is invalid (caught and re-raised as BadRequestError)
    """
    try:
        # Extract token from Authorization header
        token = extract_auth_token(app.current_event.headers)
        
        # Verify JWT
        jwt_secret = get_jwt_secret()
        payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        
        # Validate jti claim exists
        token_id = payload.get('jti')
        if not token_id:
            raise BadRequestError("Invalid token: missing jti claim")
        
        # Validate token is one-time use (check and delete from DynamoDB)
        table = get_dynamodb_table()
        response = table.get_item(Key={'state': f"{TOKEN_PREFIX}{token_id}"})
        
        if 'Item' not in response:
            logger.warning("Token already used or expired", extra={"token_id": token_id})
            raise BadRequestError("Token already used or expired")
        
        # Delete token (one-time use)
        table.delete_item(Key={'state': f"{TOKEN_PREFIX}{token_id}"})
        logger.info("Token validated and consumed", extra={"token_id": token_id})
        
        # Return user info (without token since it's one-time use)
        return {
            'user_id': payload.get('user_id'),
            'username': payload.get('username'),
            'context_title': payload.get('context_title'),
            'context': payload.get('context')
        }
        
    except jwt.ExpiredSignatureError:
        logger.warning("Expired JWT token")
        raise BadRequestError("Session expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        raise BadRequestError("Invalid session")

@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST, log_event=True)
@tracer.capture_lambda_handler
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Lambda handler for API Gateway events.
    
    Main entry point for the Lambda function that routes requests to the
    appropriate handler based on the HTTP method and path.
    
    Args:
        event: API Gateway event containing request details
        context: Lambda runtime context
        
    Returns:
        dict: API Gateway response with status code, headers, and body
    """
    return app.resolve(event, context)

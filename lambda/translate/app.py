"""Lambda function for translating text to French using Amazon Bedrock.

This module provides a REST API endpoint that accepts text and translates it
to French using Amazon Bedrock's AI models. It uses AWS Lambda Powertools
for structured logging and request validation.
"""

import os
import boto3

from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from aws_lambda_powertools.event_handler.exceptions import (
    BadRequestError,
    ServiceError,
    InternalServerError,
)
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.utilities.typing import LambdaContext
from pydantic import BaseModel

logger = Logger()
tracer = Tracer()
app = APIGatewayRestResolver(enable_validation=True)

INFERENCE_PROFILE_ID = os.environ.get("INFERENCE_PROFILE_ID")
if not INFERENCE_PROFILE_ID:
    raise ValueError("INFERENCE_PROFILE_ID environment variable is required")

bedrock_client = boto3.client("bedrock-runtime")


class TranslateRequest(BaseModel):
    """
    Request model for translation endpoint.

    Attributes:
        prompt (str): The text to be translated into French
    """

    prompt: str


@logger.inject_lambda_context(
    correlation_id_path=correlation_paths.API_GATEWAY_HTTP, log_event=True
)
@tracer.capture_lambda_handler
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """
    AWS Lambda handler function that processes API Gateway events.

    Args:
        event (dict): The AWS Lambda event object from API Gateway
        context (LambdaContext): The AWS Lambda context object

    Returns:
        dict: The API response
    """
    return app.resolve(event, context)


@app.post("/translate")
def call_bedrock(translate_request: TranslateRequest):
    """
    Endpoint handler that translates text to French using Amazon Bedrock.

    Args:
        translate_request (TranslateRequest): The translation request containing the text to translate

    Returns:
        dict: Contains the translated text in the 'output' field

    Raises:
        Exception: For various error conditions (validation error, model not ready, throttling, etc.)
    """
    conversation = [
        {
            "role": "user",
            "content": [
                {
                    "text": f"I would like you to translate the following content into French. Just give me the translation and no more: {translate_request.prompt}"
                }
            ],
        }
    ]

    # Send the message to the model, using a default inference configuration.
    try:
        response = bedrock_client.converse(
            modelId=INFERENCE_PROFILE_ID,
            messages=conversation,
            inferenceConfig={"maxTokens": 512, "temperature": 0.5, "topP": 0.9},
        )
    except bedrock_client.exceptions.ValidationException as e:
        logger.error(f"Validation error when calling Bedrock: {str(e)}")
        raise BadRequestError("Invalid request parameters")
    except bedrock_client.exceptions.ModelNotReadyException as e:
        logger.error(f"Model not ready: {str(e)}")
        raise ServiceError("Model is currently unavailable")
    except bedrock_client.exceptions.ThrottlingException as e:
        logger.error(f"Request throttled: {str(e)}")
        raise ServiceError("Too many requests, please try again later")
    except Exception as e:
        logger.exception("Unexpected error calling Bedrock")
        raise InternalServerError("Internal server error") from e

    # Extract the response text.
    try:
        response_text = response["output"]["message"]["content"][0]["text"]
        logger.debug(f"Response from Bedrock: {response_text}")
        return {"output": response_text}
    except (KeyError, IndexError, TypeError) as e:
        logger.warning(f"Unexpected response structure from Bedrock: {str(e)}")
        raise InternalServerError("Failed to parse translation response")

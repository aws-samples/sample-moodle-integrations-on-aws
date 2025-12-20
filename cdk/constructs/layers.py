from constructs import Construct
from aws_cdk import (
    aws_lambda as _lambda,
    Stack,
)


class LayersConstruct(Construct):
    """Shared Lambda layers for the stack"""

    def __init__(self, scope, construct_id):
        super().__init__(scope, construct_id)

        stack = Stack.of(self)

        # Get Powertools layer version from context
        powertools_version = stack.node.try_get_context("powertools_layer_version")
        if not powertools_version:
            raise ValueError("powertools_layer_version must be provided in context")

        # AWS Lambda Powertools layer (managed by AWS) - Version 3
        self.powertools_layer = _lambda.LayerVersion.from_layer_version_arn(
            self,
            "PowertoolsLayer",
            f"arn:aws:lambda:{stack.region}:017000801446:layer:AWSLambdaPowertoolsPythonV3-python314-arm64:{powertools_version}",
        )

        # Shared requests layer with bundling
        self.requests_layer = _lambda.LayerVersion(
            self,
            "RequestsLayer",
            code=_lambda.Code.from_asset(
                "layers/requests",
                bundling={
                    "image": _lambda.Runtime.PYTHON_3_14.bundling_image,
                    "command": [
                        "bash",
                        "-c",
                        "pip install -r requirements.txt -t /asset-output/python",
                    ],
                },
            ),
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_14],
            compatible_architectures=[_lambda.Architecture.ARM_64],
            description="Requests library",
        )

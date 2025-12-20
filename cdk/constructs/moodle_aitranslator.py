import os
from constructs import Construct
from cdk_nag import NagSuppressions
from aws_cdk import (
    aws_apigateway as apigateway,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_iam as iam,
    CfnOutput,
    RemovalPolicy,
    Duration,
    Stack,
)
from aws_cdk.aws_bedrock_alpha import BedrockFoundationModel


class MoodleAiTranslatorConstruct(Construct):
    def __init__(
        self,
        scope,
        construct_id,
        api: apigateway.RestApi,
        lambda_authorizer: apigateway.TokenAuthorizer,
        powertools_layer=None,
    ):
        super().__init__(scope, construct_id)

        stack = Stack.of(self)

        # Get inference profile from context or determine from region
        inference_profile_id = stack.node.try_get_context("nova_pro_inference_profile")
        
        if not inference_profile_id:
            region = os.environ.get("CDK_DEFAULT_REGION", "us-west-2")
            
            # Map regions to inference profiles (explicit list from AWS)
            region_map = {
                "us-east-1": "us.amazon.nova-pro-v1:0",
                "us-east-2": "us.amazon.nova-pro-v1:0",
                "us-west-1": "us.amazon.nova-pro-v1:0",
                "us-west-2": "us.amazon.nova-pro-v1:0",
                "eu-north-1": "eu.amazon.nova-pro-v1:0",
                "eu-west-1": "eu.amazon.nova-pro-v1:0",
                "eu-west-3": "eu.amazon.nova-pro-v1:0",
                "eu-central-1": "eu.amazon.nova-pro-v1:0",
                "ap-south-1": "apac.amazon.nova-pro-v1:0",
                "ap-northeast-1": "apac.amazon.nova-pro-v1:0",
                "ap-northeast-2": "apac.amazon.nova-pro-v1:0",
                "ap-southeast-1": "apac.amazon.nova-pro-v1:0",
                "ap-southeast-2": "apac.amazon.nova-pro-v1:0",
            }
            
            if region in region_map:
                inference_profile_id = region_map[region]
            else:
                # Fallback to foundation model for unsupported regions
                model = BedrockFoundationModel.AMAZON_NOVA_PRO_V1
                inference_profile_id = model.model_id

        translate_function_log_group = logs.LogGroup(
            self,
            "TranslateLogGroup",
            log_group_name=f"/aws/lambda/{stack.stack_name}-TranslateFunction",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        translate_function_role = iam.Role(
            self,
            "TranslateFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "LogsAndTracingPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                            resources=[translate_function_log_group.log_group_arn],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "xray:PutTraceSegments",
                                "xray:PutTelemetryRecords",
                            ],
                            resources=[
                                f"arn:aws:xray:{stack.region}:{stack.account}:*"
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=["bedrock:InvokeModel"],
                            resources=[
                                f"arn:{stack.partition}:bedrock:{stack.region}:{stack.account}:inference-profile/{inference_profile_id}",
                                f"arn:{stack.partition}:bedrock:*::foundation-model/amazon.nova-pro-v1:0",
                            ],
                        ),
                    ]
                )
            },
        )
        NagSuppressions.add_resource_suppressions(
            translate_function_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "X-Ray tracing requires account-scoped wildcard permissions. Bedrock foundation model uses wildcard region for cross-region access.",
                    "appliesTo": [
                        "Resource::arn:aws:xray:<AWS::Region>:<AWS::AccountId>:*",
                        "Resource::arn:<AWS::Partition>:bedrock:*::foundation-model/amazon.nova-pro-v1:0",
                    ],
                }
            ],
            apply_to_children=True,
        )

        translate_function = _lambda.Function(
            self,
            "TranslateFunction",
            code=_lambda.Code.from_asset("lambda/translate"),
            handler="app.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_14,
            architecture=_lambda.Architecture.ARM_64,
            memory_size=256,
            timeout=Duration.seconds(30),
            role=translate_function_role,
            layers=[powertools_layer],
            log_group=translate_function_log_group,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "POWERTOOLS_METRICS_NAMESPACE": "moodle-plugins",
                "POWERTOOLS_SERVICE_NAME": "Translator",
                "LOG_LEVEL": "INFO",
                "INFERENCE_PROFILE_ID": inference_profile_id,
            },
        )

        # Suppress CDK-nag for any default policy created by the translate function
        NagSuppressions.add_resource_suppressions_by_path(
            stack,
            "/moodle-plugins/MoodleAiTranslator/TranslateFunctionRole/DefaultPolicy",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Lambda function may create default policy with wildcard permissions for service integrations",
                    "appliesTo": ["Resource::*"],
                }
            ],
        )

        # Create translate resource
        translate_resource = api.root.add_resource("translate")

        # Add POST method to translate resource
        translate_method = translate_resource.add_method(
            "POST",
            integration=apigateway.LambdaIntegration(translate_function),
            authorizer=lambda_authorizer,
            authorization_type=apigateway.AuthorizationType.CUSTOM,
            method_responses=[
                apigateway.MethodResponse(
                    status_code="200",
                ),
            ],
        )

        NagSuppressions.add_resource_suppressions(
            translate_method,
            [
                {
                    "id": "AwsSolutions-COG4",
                    "reason": "Using Lambda authorizer for custom authorization logic instead of Cognito",
                }
            ],
        )

        # Output the API Gateway Translate endpoint
        CfnOutput(
            self,
            "TranslateEndpoint",
            value=f"{api.url}translate",
            description="API Gateway Translate endpoint URL",
        )

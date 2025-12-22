from constructs import Construct
from cdk_nag import NagSuppressions
from aws_cdk import (
    aws_apigateway as apigateway,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_iam as iam,
    RemovalPolicy,
    Duration,
    Stack,
)


class APIGatewayConstruct(Construct):
    def __init__(
        self,
        scope,
        construct_id,
        moodle_url: str,
        jwt_secret_param=None,
        powertools_layer=None,
        requests_layer=None,
    ):
        super().__init__(scope, construct_id)

        stack = Stack.of(self)

        # Create API for tools to use
        self.api = apigateway.RestApi(
            self,
            id="MoodleAiApi",
            rest_api_name="MoodleAiApi",
            description="Moodle AWS Integrations",
            deploy=True,
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.REGIONAL]
            ),
            deploy_options=apigateway.StageOptions(
                stage_name="v1",
                metrics_enabled=True,
            ),
        )

        # Add request validator
        self.api.add_request_validator(
            "RequestValidator",
            validate_request_body=True,
            validate_request_parameters=True,
        )

        NagSuppressions.add_resource_suppressions(
            self.api.deployment_stage,
            [
                {
                    "id": "AwsSolutions-APIG3",
                    "reason": "WAF is not required for this sample API",
                },
                {
                    "id": "AwsSolutions-APIG1",
                    "reason": "Access logging requires account-level CloudWatch role",
                },
                {
                    "id": "AwsSolutions-APIG6",
                    "reason": "Execution logging requires account-level CloudWatch role",
                },
            ],
        )

        # Create log group for authorizer function
        authorizer_log_group = logs.LogGroup(
            self,
            "MoodleAuthorizerLogGroup",
            log_group_name=f"/aws/lambda/{stack.stack_name}-MoodleAuthorizer",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create role for authorizer function
        authorizer_role = iam.Role(
            self,
            "MoodleAuthorizerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "LogsAndTracingPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                            resources=[authorizer_log_group.log_group_arn],
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
                    ]
                )
            },
        )
        NagSuppressions.add_resource_suppressions(
            authorizer_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "X-Ray tracing requires account-scoped wildcard permissions for trace segments and telemetry records",
                    "appliesTo": [
                        "Resource::arn:aws:xray:<AWS::Region>:<AWS::AccountId>:*",
                    ],
                }
            ],
            apply_to_children=True,
        )

        # Create Lambda authorizer function
        authorizer_function = _lambda.Function(
            self,
            id="MoodleAuthorizer",
            runtime=_lambda.Runtime.PYTHON_3_14,
            architecture=_lambda.Architecture.ARM_64,
            handler="app.lambda_handler",
            code=_lambda.Code.from_asset("lambda/moodle_authorizer"),
            role=authorizer_role,
            timeout=Duration.seconds(30),
            layers=[powertools_layer, requests_layer],
            log_group=authorizer_log_group,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "MOODLE_URL": moodle_url,
                "JWT_SECRET_NAME": (
                    jwt_secret_param.secret_name if jwt_secret_param else ""
                ),
                "POWERTOOLS_SERVICE_NAME": "moodle-authorizer",
                "LOG_LEVEL": "INFO",
            },
        )

        # Grant access to JWT secret if provided
        if jwt_secret_param:
            jwt_secret_param.grant_read(authorizer_function)
            # Suppress CDK-nag for the default policy created by grant_read
            NagSuppressions.add_resource_suppressions_by_path(
                stack,
                "/moodle-plugins/API/MoodleAuthorizerRole/DefaultPolicy",
                [
                    {
                        "id": "AwsSolutions-IAM5",
                        "reason": "Secrets Manager grant_read creates wildcard permissions for secret access",
                        "appliesTo": ["Resource::*"],
                    }
                ],
            )

        # Create Lambda authorizer
        self.lambda_authorizer = apigateway.TokenAuthorizer(
            self,
            id="LambdaAuthorizer",
            handler=authorizer_function,
            identity_source=apigateway.IdentitySource.header("Authorization"),
            results_cache_ttl=Duration.minutes(5),  # Cache for 5 minutes
        )

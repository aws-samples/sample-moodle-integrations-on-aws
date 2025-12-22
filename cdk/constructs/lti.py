from constructs import Construct
from cdk_nag import NagSuppressions
from aws_cdk import (
    aws_apigateway as apigateway,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_secretsmanager as secretsmanager,
    aws_ssm as ssm,
    custom_resources as cr,
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
)


class LtiConstruct(Construct):
    def __init__(
        self,
        scope,
        construct_id,
        moodle_url: str,
        powertools_layer=None,
        log_bucket=None,
        **kwargs,
    ):
        super().__init__(scope, construct_id)

        stack = Stack.of(self)

        # S3 bucket to host the React app
        website_bucket = s3.Bucket(
            self,
            "WebsiteBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=log_bucket,
            server_access_logs_prefix="s3-access-logs/",
        )

        # CloudFront Origin Access Control
        oac = cloudfront.S3OriginAccessControl(self, "OAC")

        # Store API origin for later use (will be set after API Gateway is created)
        self.api_origin = None

        # CloudFront distribution for the website
        distribution = cloudfront.Distribution(
            self,
            "Distribution",
            comment="Distribution for LTI Tool",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(
                    website_bucket,
                    origin_id=oac.origin_access_control_id,
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                )
            ],
            log_bucket=log_bucket,
            log_file_prefix="cloudfront-logs/",
        )

        # Grant CloudFront access to S3 bucket
        website_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[website_bucket.arn_for_objects("*")],
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::{stack.account}:distribution/{distribution.distribution_id}"
                    }
                },
            )
        )
        NagSuppressions.add_resource_suppressions(
            distribution,
            [
                {
                    "id": "AwsSolutions-CFR1",
                    "reason": "Geo restrictions not required for this solution",
                },
                {
                    "id": "AwsSolutions-CFR2",
                    "reason": "WAF not required for the solution",
                },
                {
                    "id": "AwsSolutions-CFR4",
                    "reason": "Using default CloudFront certificate, TLS 1.2 enforcement requires custom certificate",
                },
            ],
        )

        # Deploy the React app to S3
        s3deploy.BucketDeployment(
            self,
            "DeployWebsite",
            sources=[s3deploy.Source.asset("lti_frontend/dist")],
            destination_bucket=website_bucket,
            distribution=distribution,
            distribution_paths=["/*"],
        )

        # Create SSM parameters with placeholders
        self.client_id_param = ssm.StringParameter(
            self,
            "ClientIdParam",
            parameter_name="/lti/client-id",
            string_value="placeholder",
        )
        self.redirect_url_param = ssm.StringParameter(
            self,
            "RedirectUriParam",
            parameter_name="/lti/redirect-uri",
            string_value="placeholder",
        )
        # Generate secure random JWT secret using Secrets Manager
        jwt_secret = secretsmanager.Secret(
            self,
            "JwtSecret",
            secret_name=f"{stack.stack_name}/lti/jwt-secret",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template="{}",  # nosec B106 - Template for AWS to generate random secret
                generate_string_key="secret",
                password_length=64,
                exclude_punctuation=True,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )
        NagSuppressions.add_resource_suppressions(
            jwt_secret,
            [
                {
                    "id": "AwsSolutions-SMG4",
                    "reason": "JWT signing secret does not require automatic rotation",
                }
            ],
        )
        self.jwt_secret_param = jwt_secret

        # DynamoDB table for state/nonce storage (CSRF protection)
        state_table = dynamodb.Table(
            self,
            "LtiStateTable",
            partition_key=dynamodb.Attribute(
                name="state", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
        )
        NagSuppressions.add_resource_suppressions(
            state_table,
            [
                {
                    "id": "AwsSolutions-DDB3",
                    "reason": "Point-in-time recovery enabled for state table",
                }
            ],
        )

        lti_function_log_group = logs.LogGroup(
            self,
            "LTILogGroup",
            log_group_name=f"/aws/lambda/{stack.stack_name}-LTIFunction",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Custom IAM role for LTI Lambda function
        lti_function_role = iam.Role(
            self,
            "LtiFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "CloudWatchLogs": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                            resources=[lti_function_log_group.log_group_arn],
                        )
                    ]
                ),
                "XRay": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "xray:PutTraceSegments",
                                "xray:PutTelemetryRecords",
                            ],
                            resources=[
                                f"arn:aws:xray:{stack.region}:{stack.account}:*"
                            ],
                        )
                    ]
                ),
            },
        )
        # Lambda function for LTI integration using Python with Lambda Powertools
        lti_function = _lambda.Function(
            self,
            "LtiFunction",
            handler="app.lambda_handler",
            code=_lambda.Code.from_asset(
                "lambda/lti",
                bundling={
                    "image": _lambda.Runtime.PYTHON_3_14.bundling_image,
                    "command": [
                        "bash",
                        "-c",
                        "pip install -r requirements.txt -t /asset-output --platform manylinux2014_aarch64 --only-binary=:all: && cp -au . /asset-output",
                    ],
                },
            ),
            runtime=_lambda.Runtime.PYTHON_3_14,
            architecture=_lambda.Architecture.ARM_64,
            memory_size=256,
            timeout=Duration.seconds(10),
            role=lti_function_role,
            layers=[powertools_layer],
            log_group=lti_function_log_group,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "WEBSITE_URL": f"https://{distribution.distribution_domain_name}",
                "MOODLE_URL": moodle_url,
                "OIDC_AUTH_URL": f"{moodle_url}/mod/lti/auth.php",
                "CLIENT_ID_PARAM": self.client_id_param.parameter_name,
                "REDIRECT_URL_PARAM": self.redirect_url_param.parameter_name,
                "JWT_SECRET_NAME": self.jwt_secret_param.secret_name,
                "STATE_TABLE_NAME": state_table.table_name,
                "POWERTOOLS_SERVICE_NAME": "lti-tool",
                "LOG_LEVEL": "INFO"
            },
        )
        self.client_id_param.grant_read(lti_function)
        self.redirect_url_param.grant_read(lti_function)
        self.jwt_secret_param.grant_read(lti_function)
        state_table.grant_read_write_data(lti_function)

        # Suppress CDK-nag for the default policy created by grant operations
        NagSuppressions.add_resource_suppressions_by_path(
            stack,
            "/moodle-plugins/LTI/LtiFunctionRole/DefaultPolicy",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "SSM parameters and DynamoDB grant operations create wildcard permissions for resource access",
                    "appliesTo": ["Resource::*"],
                }
            ],
        )

        self.lti_function = lti_function
        self.lti_resource = None
        self.distribution = distribution

        NagSuppressions.add_resource_suppressions(
            lti_function_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "SSM parameter ARN patterns and X-Ray require account-scoped wildcard permissions",
                    "appliesTo": [
                        "Resource::arn:aws:xray:<AWS::Region>:<AWS::AccountId>:*",
                        f"Resource::<ClientIdParam{self.client_id_param.node.addr[-8:]}.Arn>:*",
                        f"Resource::<RedirectUriParam{self.redirect_url_param.node.addr[-8:]}.Arn>:*",
                        f"Resource::<JwtSecret{self.jwt_secret_param.node.addr[-8:]}.Arn>:*",
                        f"Resource::<LtiStateTable{state_table.node.addr[-8:]}.Arn>/index/*",
                    ],
                }
            ],
            apply_to_children=True,
        )

    def add_api_endpoints(self, api: apigateway.RestApi):
        """Add LTI endpoints to the API Gateway"""

        stack = Stack.of(self)

        # Add API Gateway as CloudFront origin for /api/* paths
        # Extract domain from API URL
        api_domain = api.url.replace("https://", "").replace("http://", "").rstrip("/")
        if "/" in api_domain:
            api_domain = api_domain.split("/")[0]

        # Create custom cache policy that includes Authorization header
        api_cache_policy = cloudfront.CachePolicy(
            self,
            "ApiCachePolicy",
            cache_policy_name=f"{stack.stack_name}-ApiCachePolicy",
            min_ttl=Duration.seconds(0),
            max_ttl=Duration.seconds(1),
            default_ttl=Duration.seconds(0),
            cookie_behavior=cloudfront.CacheCookieBehavior.none(),
            header_behavior=cloudfront.CacheHeaderBehavior.allow_list("Authorization"),
            query_string_behavior=cloudfront.CacheQueryStringBehavior.all(),
            enable_accept_encoding_gzip=True,
            enable_accept_encoding_brotli=True,
        )

        # Create custom origin request policy
        api_origin_request_policy = cloudfront.OriginRequestPolicy(
            self,
            "ApiOriginRequestPolicy",
            origin_request_policy_name=f"{stack.stack_name}-ApiOriginRequestPolicy",
            cookie_behavior=cloudfront.OriginRequestCookieBehavior.none(),
            header_behavior=cloudfront.OriginRequestHeaderBehavior.allow_list(
                "Accept", "Accept-Language", "Origin", "Referer"
            ),
            query_string_behavior=cloudfront.OriginRequestQueryStringBehavior.all(),
        )

        # Add behavior for /api/* to route to API Gateway
        api_origin = origins.HttpOrigin(
            api_domain,
            origin_path="/v1",  # Include API Gateway stage
            protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
        )

        self.distribution.add_behavior(
            "/api/*",
            api_origin,
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
            allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
            cache_policy=api_cache_policy,
            origin_request_policy=api_origin_request_policy,
        )

        # Add LTI login endpoint
        self.lti_resource = api.root.add_resource("lti")
        login_resource = self.lti_resource.add_resource("login")

        # POST method for LTI login
        login_method = login_resource.add_method(
            "POST", apigateway.LambdaIntegration(self.lti_function, proxy=True)
        )
        NagSuppressions.add_resource_suppressions(
            login_method,
            [
                {
                    "id": "AwsSolutions-APIG4",
                    "reason": "LTI login endpoint must be publicly accessible as it's the entry point for LTI authentication",
                },
                {
                    "id": "AwsSolutions-COG4",
                    "reason": "LTI login endpoint must be publicly accessible as it's the entry point for LTI authentication",
                },
            ],
        )

        # Add LTI launch endpoint
        launch_resource = self.lti_resource.add_resource("launch")

        # POST method for LTI launch
        launch_method = launch_resource.add_method(
            "POST", apigateway.LambdaIntegration(self.lti_function, proxy=True)
        )
        NagSuppressions.add_resource_suppressions(
            launch_method,
            [
                {
                    "id": "AwsSolutions-APIG4",
                    "reason": "LTI launch endpoint must be publicly accessible for LTI protocol flow",
                },
                {
                    "id": "AwsSolutions-COG4",
                    "reason": "LTI launch endpoint must be publicly accessible for LTI protocol flow",
                },
            ],
        )

        # Add API resource for authenticated endpoints
        api_resource = api.root.add_resource("api")
        user_resource = api_resource.add_resource("user")
        info_resource = user_resource.add_resource("info")

        # GET /api/user/info endpoint (no authorizer - uses cookie)
        info_method = info_resource.add_method(
            "GET", apigateway.LambdaIntegration(self.lti_function, proxy=True)
        )
        NagSuppressions.add_resource_suppressions(
            info_method,
            [
                {
                    "id": "AwsSolutions-APIG4",
                    "reason": "User info endpoint validates JWT from cookie internally",
                },
                {
                    "id": "AwsSolutions-COG4",
                    "reason": "User info endpoint validates JWT from cookie internally",
                },
            ],
        )

        # Update SSM parameter with API Gateway URL using Custom Resource
        # Use API Gateway directly for launch to allow Set-Cookie header
        cr.AwsCustomResource(
            self,
            "UpdateRedirectUri",
            on_create=cr.AwsSdkCall(
                service="SSM",
                action="putParameter",
                parameters={
                    "Name": self.redirect_url_param.parameter_name,
                    "Value": f"{api.url.rstrip('/')}{launch_resource.path}",
                    "Overwrite": True,
                },
                physical_resource_id=cr.PhysicalResourceId.of("redirect-uri-updater"),
            ),
            on_update=cr.AwsSdkCall(
                service="SSM",
                action="putParameter",
                parameters={
                    "Name": self.redirect_url_param.parameter_name,
                    "Value": f"{api.url.rstrip('/')}{launch_resource.path}",
                    "Overwrite": True,
                },
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        actions=["ssm:PutParameter"],
                        resources=[self.redirect_url_param.parameter_arn],
                    )
                ]
            ),
        )

        # Output the CloudFront URL
        CfnOutput(
            self,
            "WebsiteURL",
            value=f"https://{self.distribution.distribution_domain_name}",
            description="Website URL (use this for all access)",
        )

        # Output the API URL through CloudFront
        CfnOutput(
            self,
            "ApiURLviaCloudFront",
            value=f"https://{self.distribution.distribution_domain_name}/api",
            description="API URL via CloudFront (for cookie-based auth)",
        )

        # Output the API Gateway URL
        CfnOutput(
            self,
            "ApiURL",
            value=api.url,
            description="API Gateway URL",
        )

        # Output the Tool URL (use API Gateway for Set-Cookie support)
        CfnOutput(
            self,
            "ToolURL",
            value=f"{api.url.rstrip('/')}{launch_resource.path}",
            description="Tool URL (Redirection URI) - use this in Moodle",
        )

        # Output the Initiate Login URL (use API Gateway)
        CfnOutput(
            self,
            "InitiateLoginURL",
            value=f"{api.url.rstrip('/')}{login_resource.path}",
            description="Initiate Login URL - use this in Moodle",
        )

        # Output the Public Keyset for the tool
        CfnOutput(
            self,
            "PublicKeyset",
            value=f"{api.url.rstrip('/')}/lti/key",
            description="Public Keyset",
        )

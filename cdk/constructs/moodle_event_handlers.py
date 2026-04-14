"""Moodle event handlers construct for EventBridge processing and KB indexing."""

from constructs import Construct
from cdk_nag import NagSuppressions
from aws_cdk import (
    aws_bedrock as bedrock,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3vectors as s3vectors,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    Duration,
    RemovalPolicy,
    SecretValue,
    Stack,
)


class MoodleEventHandlersConstruct(Construct):

    def __init__(
        self,
        scope,
        construct_id,
        qualifier: str,
        moodle_event_bus: events.EventBus,
        moodle_domain: str,
        powertools_layer=None,
        requests_layer=None,
        python_pptx_layer=None,
    ):
        super().__init__(scope, construct_id)

        stack = Stack.of(self)

        index_moodle_file_function_log_group = logs.LogGroup(
            self,
            "IndexMoodleFileFunctionLogGroup",
            log_group_name=f"/aws/lambda/{stack.stack_name}-IndexMoodleFileFunction",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        moodle_token_secret = secretsmanager.Secret(
            self,
            "MoodleTokenSecret",
            description="Moodle API access token",
            secret_string_value=SecretValue.unsafe_plain_text("Placeholder"),
            removal_policy=RemovalPolicy.DESTROY,
        )
        NagSuppressions.add_resource_suppressions(
            moodle_token_secret,
            [
                {
                    "id": "AwsSolutions-SMG4",
                    "reason": "This is a Moodle provided secret, this secret should be manually rotated frequently in line with customer secret management policies",
                }
            ],
        )

        # S3 Vectors resources for Knowledge Base
        # Create a vector bucket (specialized S3 bucket for vector storage)
        vector_bucket = s3vectors.CfnVectorBucket(
            self,
            "KBVectorBucket",
            vector_bucket_name=f"{stack.stack_name.lower()}-kb-vectors-{stack.account}",
            encryption_configuration=s3vectors.CfnVectorBucket.EncryptionConfigurationProperty(
                sse_type="AES256"
            ),
        )
        vector_bucket.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create a vector index within the vector bucket
        # Titan Embed Text v2 uses 1024 dimensions
        # CRITICAL: Mark AMAZON_BEDROCK_TEXT as non-filterable to avoid 2KB filterable metadata limit
        # Bedrock stores chunk text in AMAZON_BEDROCK_TEXT metadata field, which can exceed 2KB
        # By marking it as non-filterable, it counts toward the 40KB total metadata limit instead
        vector_index = s3vectors.CfnIndex(
            self,
            "KBVectorIndex",
            vector_bucket_arn=vector_bucket.attr_vector_bucket_arn,
            index_name=f"{stack.stack_name.lower()}-moodle-index",
            data_type="float32",
            dimension=1024,  # Titan Embed Text v2 dimension
            distance_metric="cosine",
            metadata_configuration=s3vectors.CfnIndex.MetadataConfigurationProperty(
                non_filterable_metadata_keys=["AMAZON_BEDROCK_TEXT"]
            ),
        )
        vector_index.add_dependency(vector_bucket)
        vector_index.apply_removal_policy(RemovalPolicy.DESTROY)

        # Bedrock Knowledge Base execution role
        kb_role = iam.Role(
            self,
            "BedrockKBRole",
            assumed_by=iam.ServicePrincipal(
                "bedrock.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": stack.account},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:{stack.partition}:bedrock:{stack.region}:{stack.account}:knowledge-base/*"
                    },
                },
            ),
            inline_policies={
                "BedrockKBPolicy": iam.PolicyDocument(
                    statements=[
                        # S3 Vectors storage permissions
                        iam.PolicyStatement(
                            actions=[
                                "s3vectors:PutVector",
                                "s3vectors:PutVectors",
                                "s3vectors:GetVector",
                                "s3vectors:GetVectors",
                                "s3vectors:DeleteVector",
                                "s3vectors:DeleteVectors",
                                "s3vectors:ListVectors",
                                "s3vectors:QueryVectors",
                            ],
                            resources=[
                                vector_bucket.attr_vector_bucket_arn,
                                f"{vector_bucket.attr_vector_bucket_arn}/*",
                            ],
                        ),
                        # Embedding model permissions
                        iam.PolicyStatement(
                            actions=["bedrock:InvokeModel"],
                            resources=[
                                f"arn:{stack.partition}:bedrock:{stack.region}::foundation-model/amazon.titan-embed-text-v2:0"
                            ],
                        ),
                    ]
                )
            },
        )

        NagSuppressions.add_resource_suppressions(
            kb_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Bedrock Knowledge Base requires wildcard permissions for S3 Vectors operations on bucket objects",
                    "appliesTo": [
                        "Resource::<MoodleEventHandlersKBVectorBucket1F67A350.VectorBucketArn>/*",
                    ],
                }
            ],
        )

        # Bedrock Knowledge Base with S3 Vectors
        knowledge_base = bedrock.CfnKnowledgeBase(
            self,
            "MoodleFilesKB",
            name=f"{stack.stack_name}-MoodleFilesKB",
            role_arn=kb_role.role_arn,
            knowledge_base_configuration=bedrock.CfnKnowledgeBase.KnowledgeBaseConfigurationProperty(
                type="VECTOR",
                vector_knowledge_base_configuration=bedrock.CfnKnowledgeBase.VectorKnowledgeBaseConfigurationProperty(
                    embedding_model_arn=f"arn:{stack.partition}:bedrock:{stack.region}::foundation-model/amazon.titan-embed-text-v2:0"
                ),
            ),
            storage_configuration=bedrock.CfnKnowledgeBase.StorageConfigurationProperty(
                type="S3_VECTORS",
                s3_vectors_configuration=bedrock.CfnKnowledgeBase.S3VectorsConfigurationProperty(
                    vector_bucket_arn=vector_bucket.attr_vector_bucket_arn,
                    index_arn=vector_index.attr_index_arn,
                ),
            ),
        )
        knowledge_base.add_dependency(vector_index)

        knowledge_base_log_group = logs.LogGroup(
            self,
            "BedrockKBLogGroup",
            log_group_name=f"/aws/bedrock/{stack.stack_name}-kb-logs",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        knowledge_base_log_delivery_source = logs.CfnDeliverySource(
            self,
            "KnowledgeBaseLogSource",
            name=f"{stack.stack_name}-KB-LogSource",
            log_type="APPLICATION_LOGS",
            resource_arn=knowledge_base.attr_knowledge_base_arn,
        )

        knowledge_base_log_delivery_destination = logs.CfnDeliveryDestination(
            self,
            "KnowledgeBaseLogDestination",
            name=f"{stack.stack_name}-KB-LogDest",
            destination_resource_arn=knowledge_base_log_group.log_group_arn,
        )

        knowledge_base_logs_resource_policy = logs.ResourcePolicy(
            self,
            "KnowledgeBaseLogDeliveryDestinationPolicyResourcePolicy",
            policy_statements=[
                iam.PolicyStatement(
                    actions=["logs:PutLogEvents", "logs:CreateLogStream"],
                    principals=[
                        iam.ServicePrincipal("delivery.logs.amazonaws.com"),
                    ],
                    resources=[
                        knowledge_base_log_delivery_destination.destination_resource_arn
                    ],
                )
            ],
        )

        knowledge_base_log_delivery = logs.CfnDelivery(
            self,
            "KnowledgeBaseLogDelivery",
            delivery_destination_arn=knowledge_base_log_delivery_destination.attr_arn,
            delivery_source_name=f"{stack.stack_name}-KB-LogSource",
        )
        knowledge_base_log_delivery.add_dependency(
            knowledge_base_logs_resource_policy.node.default_child
        )
        knowledge_base_log_delivery.add_dependency(knowledge_base_log_delivery_source)

        knowledge_base_data_source = bedrock.CfnDataSource(
            self,
            "MoodleDataSource",
            name=f"{stack.stack_name}-MoodleDataSource",
            knowledge_base_id=knowledge_base.attr_knowledge_base_id,
            data_deletion_policy="RETAIN",
            data_source_configuration=bedrock.CfnDataSource.DataSourceConfigurationProperty(
                type="CUSTOM"
            ),
        )

        # S3 staging bucket for large file ingestion into Knowledge Base.
        # Files exceeding the 6MB IngestKnowledgeBaseDocuments API limit are
        # uploaded here first, then referenced via S3 location during ingestion.
        kb_staging_bucket = s3.Bucket(
            self,
            "KBStagingBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            lifecycle_rules=[
                s3.LifecycleRule(expiration=Duration.days(1)),
            ],
        )

        NagSuppressions.add_resource_suppressions(
            kb_staging_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "Staging bucket for temporary KB ingestion files; access logging not required for short-lived objects",
                }
            ],
        )

        index_moodle_file_function_role = iam.Role(
            self,
            "IndexMoodleFileFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "LogsAndTracingPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                            resources=[
                                index_moodle_file_function_log_group.log_group_arn
                            ],
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

        index_moodle_file_function = _lambda.Function(
            self,
            "IndexMoodleFileFunction",
            code=_lambda.Code.from_asset("lambda/index_moodle_file"),
            handler="app.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_14,
            architecture=_lambda.Architecture.ARM_64,
            memory_size=256,
            timeout=Duration.seconds(30),
            role=index_moodle_file_function_role,
            layers=[powertools_layer, requests_layer, python_pptx_layer],
            log_group=index_moodle_file_function_log_group,
            tracing=_lambda.Tracing.ACTIVE,
            reserved_concurrent_executions=1,
            environment={
                "POWERTOOLS_METRICS_NAMESPACE": "moodle-plugins",
                "POWERTOOLS_SERVICE_NAME": "IndexMoodleFile",
                "LOG_LEVEL": "INFO",
                "MOODLE_DNS": moodle_domain,
                "MOODLE_TOKEN_SECRET_NAME": moodle_token_secret.secret_name,
                "KNOWLEDGE_BASE_ID": knowledge_base.attr_knowledge_base_id,
                "DATA_SOURCE_ID": knowledge_base_data_source.attr_data_source_id,
                "KB_STAGING_BUCKET": kb_staging_bucket.bucket_name,
                "AWS_ACCOUNT_ID": stack.account,
            },
        )
        NagSuppressions.add_resource_suppressions(
            index_moodle_file_function_role,
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

        moodle_token_secret.grant_read(index_moodle_file_function)

        # Suppress CDK-nag for the default policy created by grant_read
        NagSuppressions.add_resource_suppressions_by_path(
            stack,
            "/moodle-plugins/MoodleEventHandlers/IndexMoodleFileFunctionRole/DefaultPolicy",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Secrets Manager grant_read creates wildcard permissions for secret access",
                    "appliesTo": ["Resource::*"],
                }
            ],
        )

        index_moodle_file_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:StartIngestionJob",
                    "bedrock:IngestKnowledgeBaseDocuments",
                    "bedrock:DeleteKnowledgeBaseDocuments",
                    "bedrock:Retrieve",
                ],
                resources=[knowledge_base.attr_knowledge_base_arn],
            )
        )

        # Grant Lambda write access to staging bucket for large files
        kb_staging_bucket.grant_put(index_moodle_file_function)

        # Grant KB role read access to staging bucket for S3-based ingestion
        kb_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[kb_staging_bucket.arn_for_objects("*")],
            )
        )

        NagSuppressions.add_resource_suppressions(
            kb_role.node.find_child("DefaultPolicy"),
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "KB role needs wildcard to read any staged file from the staging bucket",
                    "appliesTo": [
                        "Resource::<MoodleEventHandlersKBStagingBucket74449C39.Arn>/*",
                    ],
                }
            ],
        )

        NagSuppressions.add_resource_suppressions(
            index_moodle_file_function.role.node.find_child("DefaultPolicy"),
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "S3 grant_put requires wildcard object key and s3:Abort* for multipart uploads",
                    "appliesTo": [
                        "Action::s3:Abort*",
                        "Resource::<MoodleEventHandlersKBStagingBucket74449C39.Arn>/*",
                    ],
                }
            ],
        )

        # DLQ for failed events
        index_moodle_file_dlq = sqs.Queue(
            self,
            "IndexMoodleFileDLQ",
            queue_name=f"{stack.stack_name}-IndexMoodleFileDLQ",
            retention_period=Duration.days(14),
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            enforce_ssl=True,
        )
        NagSuppressions.add_resource_suppressions(
            index_moodle_file_dlq,
            [
                {
                    "id": "AwsSolutions-SQS3",
                    "reason": "This queue is itself a DLQ for EventBridge events and does not need its own DLQ",
                }
            ],
        )

        events.Rule(
            self,
            "IndexMoodleFileRule",
            event_bus=moodle_event_bus,
            event_pattern=events.EventPattern(
                source=["moodle.events"],
                detail={
                    "eventname": ["\\core\\event\\course_module_created"],
                    "action": ["created"],
                },
            ),
            targets=[
                events_targets.LambdaFunction(
                    index_moodle_file_function,
                    dead_letter_queue=index_moodle_file_dlq,
                )
            ],
        )

        events.Rule(
            self,
            "DeleteMoodleFileRule",
            event_bus=moodle_event_bus,
            event_pattern=events.EventPattern(
                source=["moodle.events"],
                detail={
                    "eventname": ["\\core\\event\\course_module_deleted"],
                    "action": ["deleted"],
                },
            ),
            targets=[
                events_targets.LambdaFunction(
                    index_moodle_file_function,
                    dead_letter_queue=index_moodle_file_dlq,
                )
            ],
        )

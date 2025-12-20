import json
from constructs import Construct
from cdk_nag import NagSuppressions
from aws_cdk import (
    aws_bedrock as bedrock,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_opensearchserverless as opensearchserverless,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    CustomResource,
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
    ):
        super().__init__(scope, construct_id)

        stack = Stack.of(self)

        delay_function_log_group = logs.LogGroup(
            self,
            "DelayLogGroup",
            log_group_name=f"/aws/lambda/{stack.stack_name}-DelayFunction",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        delay_function_role = iam.Role(
            self,
            "DelayFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "LogsAndTracingPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                            resources=[delay_function_log_group.log_group_arn],
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

        delay_function = _lambda.Function(
            self,
            "DelayFunction",
            code=_lambda.Code.from_asset(
                "lambda/delay",
                bundling={
                    "image": _lambda.Runtime.PYTHON_3_14.bundling_image,
                    "command": [
                        "bash",
                        "-c",
                        "pip install -r requirements.txt -t /asset-output && cp -au . /asset-output",
                    ],
                },
            ),
            handler="app.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_14,
            architecture=_lambda.Architecture.ARM_64,
            memory_size=128,
            timeout=Duration.seconds(900),
            role=delay_function_role,
            layers=[powertools_layer],
            log_group=delay_function_log_group,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "POWERTOOLS_METRICS_NAMESPACE": "moodle-plugins",
                "POWERTOOLS_SERVICE_NAME": "Delay",
                "LOG_LEVEL": "INFO",
            },
        )
        NagSuppressions.add_resource_suppressions(
            delay_function_role,
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

        # Suppress CDK-nag for any default policy created by the delay function
        NagSuppressions.add_resource_suppressions_by_path(
            stack,
            "/moodle-plugins/MoodleEventHandlers/DelayFunctionRole/DefaultPolicy",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Lambda function may create default policy with wildcard permissions for service integrations",
                    "appliesTo": ["Resource::*"],
                }
            ],
        )

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

        # OpenSearch Serverless encryption policy
        encryption_policy = opensearchserverless.CfnSecurityPolicy(
            self,
            "KBEncryptionPolicy",
            name="moodle-kb-encryption",
            type="encryption",
            policy=json.dumps(
                {
                    "Rules":[
                        {
                            "ResourceType":"collection",
                            "Resource":["collection/moodle-kb"]
                        }
                    ],
                    "AWSOwnedKey":True
                }  
            ),
        )

        # OpenSearch Serverless network access policy
        network_policy = opensearchserverless.CfnSecurityPolicy(
            self,
            "KBNetworkPolicy",
            name="moodle-kb-network",
            type="network",
            policy=json.dumps(
                [
                    {
                        "Rules":[
                            {
                                "ResourceType":"collection",
                                "Resource":["collection/moodle-kb"]
                            },
                            {
                                "ResourceType":"dashboard",
                                "Resource":["collection/moodle-kb"]
                            }
                        ],
                        "AllowFromPublic":True
                    }
                ]
            ),
        )

        # OpenSearch Serverless collection for Knowledge Base
        kb_collection = opensearchserverless.CfnCollection(
            self,
            "KBCollection",
            name="moodle-kb",
            type="VECTORSEARCH",
            standby_replicas="DISABLED",
        )
        kb_collection.add_dependency(encryption_policy)
        kb_collection.add_dependency(network_policy)

        # Bedrock Knowledge Base execution role
        kb_role = iam.Role(
            self,
            "BedrockKBRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
            inline_policies={
                "BedrockKBPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["aoss:APIAccessAll"],
                            resources=[kb_collection.attr_arn],
                        ),
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

        # OpenSearch Serverless data access policy
        data_access_policy = opensearchserverless.CfnAccessPolicy(
            self,
            "KBDataAccessPolicy",
            name="moodle-kb-access",
            type="data",
            policy=json.dumps(
                [
                    {
                        "Rules": [
                            {
                                "ResourceType": "collection",
                                "Resource": [f"collection/{kb_collection.name}"],
                                "Permission": [
                                    "aoss:CreateCollectionItems",
                                    "aoss:DeleteCollectionItems",
                                    "aoss:UpdateCollectionItems",
                                    "aoss:DescribeCollectionItems",
                                ],
                            },
                            {
                                "ResourceType": "index",
                                "Resource": [f"index/{kb_collection.name}/*"],
                                "Permission": [
                                    "aoss:CreateIndex",
                                    "aoss:DeleteIndex",
                                    "aoss:UpdateIndex",
                                    "aoss:DescribeIndex",
                                    "aoss:ReadDocument",
                                    "aoss:WriteDocument",
                                ],
                            },
                        ],
                        "Principal": [
                            kb_role.role_arn,
                            f"arn:{stack.partition}:iam::{stack.account}:role/cdk-{qualifier}-cfn-exec-role-{stack.account}-{stack.region}",
                        ],
                    }
                ],
                indent=2,
            ),
        )

        # OpenSearch Serverless vector index
        index_name = "moodle-index"
        kb_index = opensearchserverless.CfnIndex(
            self,
            "moodle-index",
            index_name=f"{index_name}",
            collection_endpoint=kb_collection.attr_collection_endpoint,
            settings={
                "index": {
                    "knn": True,
                }
            },
            mappings={
                "properties": {
                    "vector": {
                        "type": "knn_vector",
                        "dimension": 1024,
                        "method": {
                            "name": "hnsw",
                            "engine": "faiss",
                            "parameters": {
                                "m": 16,
                                "ef_construction": 512,
                            },
                            "space_type": "l2",
                        },
                    },
                    "text": {
                        "type": "text",
                    },
                    "metadata": {
                        "type": "text",
                        "index": False,
                    },
                }
            },
        )
        kb_index.add_dependency(data_access_policy)

        delay_function_custom = CustomResource(
            stack,
            "DelayFunctionCustom",
            service_token=delay_function.function_arn,
            properties={"SleepSeconds": 30},
            service_timeout=Duration.minutes(2),
        )
        delay_function_custom.node.add_dependency(kb_index)

        # Bedrock Knowledge Base
        knowledge_base = bedrock.CfnKnowledgeBase(
            self,
            "MoodleFilesKB",
            name=f"{stack.stack_name}-MoodleFiles",
            role_arn=kb_role.role_arn,
            knowledge_base_configuration=bedrock.CfnKnowledgeBase.KnowledgeBaseConfigurationProperty(
                type="VECTOR",
                vector_knowledge_base_configuration=bedrock.CfnKnowledgeBase.VectorKnowledgeBaseConfigurationProperty(
                    embedding_model_arn=f"arn:{stack.partition}:bedrock:{stack.region}::foundation-model/amazon.titan-embed-text-v2:0"
                ),
            ),
            storage_configuration=bedrock.CfnKnowledgeBase.StorageConfigurationProperty(
                type="OPENSEARCH_SERVERLESS",
                opensearch_serverless_configuration=bedrock.CfnKnowledgeBase.OpenSearchServerlessConfigurationProperty(
                    collection_arn=kb_collection.attr_arn,
                    vector_index_name=index_name,
                    field_mapping=bedrock.CfnKnowledgeBase.OpenSearchServerlessFieldMappingProperty(
                        vector_field="vector",
                        text_field="text",
                        metadata_field="metadata",
                    ),
                ),
            ),
        )
        knowledge_base.add_dependency(delay_function_custom.node.default_child)

        knowledge_base_log_group = logs.LogGroup(
            self,
            "BedrockKBLogGroup",
            log_group_name=f"/aws/bedrock/{stack.stack_name}-knowledgebases",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        knowledge_base_log_delivery_source = logs.CfnDeliverySource(
            self,
            "KnowledgeBaseLogSource",
            name=f"{stack.stack_name}-KnowledgeBaseLogSource",
            log_type="APPLICATION_LOGS",
            resource_arn=knowledge_base.attr_knowledge_base_arn,
        )

        knowledge_base_log_delivery_destination = logs.CfnDeliveryDestination(
            self,
            "KnowledgeBaseLogDestination",
            name=f"{stack.stack_name}-KnowledgeBaseLogDestination",
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
            delivery_source_name=f"{stack.stack_name}-KnowledgeBaseLogSource",
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
            layers=[powertools_layer, requests_layer],
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
                ],
                resources=[knowledge_base.attr_knowledge_base_arn],
            )
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

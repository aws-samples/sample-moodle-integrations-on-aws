#!/usr/bin/env python3
import os
import json
from pathlib import Path

from aws_cdk import App, Aspects

from cdk.cdk_stack import CdkStack
from cdk_nag import AwsSolutionsChecks, NagSuppressions

app = App()

qualifier = "moodle-plug"

# Add cdk-nag AwsSolutionsChecks to your app
Aspects.of(app).add(AwsSolutionsChecks())

# Load local configuration if it exists
local_config_path = Path("cdk.local.json")
if local_config_path.exists():
    try:
        with open(local_config_path, encoding="utf-8") as f:
            local_config = json.load(f)
            if not isinstance(local_config, dict):
                raise ValueError("Configuration file must contain a JSON object")
            context = local_config.get("context", {})
            if not isinstance(context, dict):
                raise ValueError("Configuration 'context' must be a JSON object")
            for key, value in context.items():
                app.node.set_context(key, value)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {local_config_path}: {e}") from e
    except (IOError, OSError) as e:
        raise ValueError(f"Failed to read {local_config_path}: {e}") from e

stack = CdkStack(
    app,
    os.getenv("STACK_NAME", "moodle-plugins"),
)

# Suppress custom resource findings (BucketDeployment and AwsCustomResource)
for child in stack.node.find_all():
    # AWS679f53fac002430cb0da5b7982bd2287 is the singleton Lambda for AwsCustomResource
    if child.node.id.startswith("Custom::CDKBucketDeployment") or child.node.id.startswith("AWS679f53fac002430cb0da5b7982bd2287"):
        NagSuppressions.add_resource_suppressions(
            child,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "CDK custom resources use AWS managed policies",
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "CDK custom resources require wildcard permissions",
                },
                {
                    "id": "AwsSolutions-L1",
                    "reason": "CDK custom resources use CDK-managed Lambda runtimes",
                },
            ],
            apply_to_children=True,
        )

app.synth()

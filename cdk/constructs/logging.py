"""Centralized logging bucket for the Moodle plugins stack."""

from constructs import Construct
from cdk_nag import NagSuppressions
from aws_cdk import (
    aws_s3 as s3,
    RemovalPolicy,
)


class LoggingConstruct(Construct):
    """Creates a centralized S3 log bucket for access logs across all constructs."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # S3 bucket for access logs (CloudFront, S3, etc.)
        self.log_bucket = s3.Bucket(
            self,
            "LogBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.OBJECT_WRITER,
        )
        NagSuppressions.add_resource_suppressions(
            self.log_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "This is the centralized log bucket, does not require its own access logs",
                }
            ],
        )
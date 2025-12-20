from aws_cdk import (
    Stack,
    CfnOutput,
)
from constructs import Construct

from .constructs.apigateway import APIGatewayConstruct
from .constructs.layers import LayersConstruct
from .constructs.logging import LoggingConstruct
from .constructs.moodle_aitranslator import MoodleAiTranslatorConstruct
from .constructs.moodle_events import MoodleEventsConstruct
from .constructs.moodle_event_handlers import MoodleEventHandlersConstruct
from .constructs.lti import LtiConstruct


class CdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Get context values for domain configuration
        domain_name = self.node.try_get_context("domain_name")
        host_name = self.node.try_get_context("host_name")
        qualifier = (
            self.node.try_get_context("@aws-cdk/core:bootstrapQualifier") or "hnb659fds"
        )

        moodle_domain = f"{host_name}.{domain_name}"
        if not domain_name or not host_name:
            raise ValueError("domain_name and host_name must be provided in context")

        moodle_role_name = self.node.try_get_context("moodle_role_name") or ""

        # Create shared layers and logging
        layers = LayersConstruct(self, "Layers")
        logging = LoggingConstruct(self, "Logging")

        moodle_events = MoodleEventsConstruct(
            self, "MoodleEvents", moodle_role_name=moodle_role_name or ""
        )

        MoodleEventHandlersConstruct(
            self,
            "MoodleEventHandlers",
            qualifier=qualifier,
            moodle_event_bus=moodle_events.moodle_event_bus,
            moodle_domain=moodle_domain,
            powertools_layer=layers.powertools_layer,
            requests_layer=layers.requests_layer,
        )

        lti = LtiConstruct(
            self,
            "LTI",
            moodle_url=f"https://{moodle_domain}",
            powertools_layer=layers.powertools_layer,
            log_bucket=logging.log_bucket,
        )

        api = APIGatewayConstruct(
            self,
            "API",
            moodle_url=f"https://{moodle_domain}",
            jwt_secret_param=lti.jwt_secret_param,
            powertools_layer=layers.powertools_layer,
            requests_layer=layers.requests_layer,
        )

        MoodleAiTranslatorConstruct(
            self,
            "MoodleAiTranslator",
            api=api.api,
            lambda_authorizer=api.lambda_authorizer,
            powertools_layer=layers.powertools_layer,
        )

        lti.add_api_endpoints(api.api)

        # CloudFormation outputs
        CfnOutput(
            self,
            "MoodleEventsIAMPolicyArn",
            value=moodle_events.moodle_events_policy.managed_policy_arn,
            description="ARN of the IAM policy for Moodle EventBridge access",
            export_name=f"{self.stack_name}-MoodleEventsIAMPolicyArn",
        )

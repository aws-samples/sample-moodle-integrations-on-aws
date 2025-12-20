from constructs import Construct
from aws_cdk import (
    aws_events as events,
    aws_iam as iam,
)


class MoodleEventsConstruct(Construct):
    def __init__(
        self,
        scope,
        construct_id,
        moodle_role_name: str,
    ):
        super().__init__(scope, construct_id)

        self.moodle_event_bus = events.EventBus(
            self, id="MoodleEventBus", event_bus_name="moodle-events"
        )

        policy_statement = iam.PolicyStatement(
            sid="AllowMoodleEvents",
            effect=iam.Effect.ALLOW,
            actions=["events:PutEvents"],
            resources=[self.moodle_event_bus.event_bus_arn],
        )

        # Always create the managed policy for use with IAM Roles Anywhere or manual IAM user/group assignment
        self.moodle_events_policy = iam.ManagedPolicy(
            self,
            id="MoodleEventsIAMPolicy",
            managed_policy_name="MoodleEventsIAMPolicy",
            description="Allows Moodle to send events to the moodle-events EventBridge event bus",
            statements=[policy_statement],
        )

        # If role name is provided and not empty, attach policy to existing role
        if moodle_role_name:
            role = iam.Role.from_role_name(
                self, "MoodleRole", role_name=moodle_role_name
            )
            self.moodle_events_policy.attach_to_role(role)

import os
import json
import base64
import requests
from dotmap import DotMap
from enum import IntEnum
from slack.errors import SlackApiError

ROLE_URL = "https://cloud.google.com/iam/docs/understanding-roles#{}"
IAM_URL = "https://console.cloud.google.com/iam-admin/iam?project={}"
LIST_TEMPLATE = ">• {label}: `{item}`"
LIST_URL_TEMPLATE = "• {label}: `<{url}|{item}>`"
PAST_TENSE_ACTION = {
    "ADD": "*_added_*",
    "REMOVE": "*_removed_*",
}


class Severity(IntEnum):
    DEFAULT = 0  # The log entry has no assigned severity level.
    DEBUG = 100  # Debug or trace information.
    INFO = 200  # Routine information, such as ongoing status or performance.
    NOTICE = 300  # Normal but significant events, such as start up, shut down, or a configuration change.
    WARNING = 400  # Warning events might cause problems.
    ERROR = 500  # Error events are likely to cause problems.
    CRITICAL = 600  # Critical events cause more severe problems or outages.
    ALERT = 700  # A person must take an action immediately.
    EMERGENCY = 800  # One or more systems are unusable.


slack_webhook = os.environ['SLACK_WEBHOOK']


def _format_message(message_info):
    message_template = f">*({message_info.severity}) {message_info.method}*\n"

    for key, value in message_info.items():
        message_template += LIST_TEMPLATE.format(label=key, item=value) + '\n'
        print(message_template)
    #     f">• status: `({message_info.status}`\n"
    #     f">• user: `{message_info.user}`\n"
    #     f">• project: `{message_info.project_id}`\n"
    #     f">:cloud: <{IAM_URL.format(message_info.project_id)}|View in Cloud Console>\n"
    # )

    return {"mrkdown": True, "text": message_template}


def _format_iam_message(message_info):
    # TODO: Create templates for each event to be handled
    # TODO: Pick template based on method
    message_template = (
        f">*(INFO) IAM Policy Update*\n"
        f">Roles were modified for an external user:\n"
        f">• user: `{message_info.user}`\n"
        f">• target_user: `{message_info.target_user}`\n"
        f">• change: {PAST_TENSE_ACTION[message_info.action]} `<{ROLE_URL.format(message_info.role)}|{message_info.role}>` role.\n"
        f">• project: `{message_info.project_id}`\n"
        f">:cloud: <{IAM_URL.format(message_info.project_id)}|View in Cloud Console>\n"
    )

    return {"mrkdown": True, "text": message_template}


def parse_base_info(message, fields=None):
    if not fields:
        fields = dict()

    fields["severity"] = message.severity
    fields["method"] = message.protoPayload.methodName
    fields[message.resource.type] = message.protoPayload.resourceName.split("/")[-1]
    fields["project_id"] = message.resource.labels.project_id
    fields["zone"] = message.resource.labels.zone
    fields["user"] = message.protoPayload.authenticationInfo.principalEmail
    return fields


def parse_iam_policy_change_info(message, fields):
    # Audit log messages for IAM policy changes have some unique fields to parse.
    policy_delta = message.protoPayload.serviceData.policyDelta
    fields["target_user"] = policy_delta.bindingDeltas[0].member.split(":")[1]
    fields["action"] = policy_delta.bindingDeltas[0].action
    fields["role"] = policy_delta.bindingDeltas[0].role.split("/")[1]
    return fields


def parse_event(event):
    message = DotMap(json.loads(base64.b64decode(event["data"]).decode("utf-8")))

    fields = parse_base_info(message)

    if fields["method"] == "SetIamPolicy":
        fields = parse_iam_policy_change_info(message, fields)

    if Severity[fields["severity"]] > Severity.INFO:
        fields["status"] = f"({str(message.protoPayload.status.code)}) {message.protoPayload.status.message}"

    return DotMap(fields)


def send_slack_alert(event, context):
    """Post a message to a slack channel.
    Args:
         event (dict):  The dictionary with data specific to this type of
         event. The `data` field contains the PubsubMessage message. The
         `attributes` field will contain custom attributes if there are any.
         context (google.cloud.functions.Context): The Cloud Functions event
         metadata. The `event_id` field contains the Pub/Sub message ID. The
         `timestamp` field contains the publish time.
    """
    formatting_handlers = {
        "SetIamPolicy": _format_iam_message,
        "default": _format_message,
    }

    try:
        parsed_event = parse_event(event)
        handler = formatting_handlers.get(parsed_event.method)
        if not handler:
            handler = formatting_handlers["default"]
        formatted_message = handler(parsed_event)
        response = requests.post(
            slack_webhook, json.dumps(formatted_message, sort_keys=True, indent=4, separators=(",", ": "))
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(e)


if __name__ == "__main__":
    # TODO: iterate over all files under test_resources dir and load them.
    with open("test_resources/external_user_policy_change.json", "rb") as json_file:
        # Simulate inbound pubsub message by base64-encoding the JSON string on the 'data' field.
        send_slack_alert(event={"data": base64.b64encode(json_file.read())}, context={})

    with open("test_resources/duplicate_snapshot_error.json", "rb") as json_file:
        # Simulate inbound pubsub message by base64-encoding the JSON string on the 'data' field.
        send_slack_alert(event={"data": base64.b64encode(json_file.read())}, context={})

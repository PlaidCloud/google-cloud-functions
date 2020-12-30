gcloud functions deploy slack-alerts --runtime=python37  --trigger-topic=alerts  --entry-point=send_slack_alert

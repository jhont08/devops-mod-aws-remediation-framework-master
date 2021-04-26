#!/usr/bin/python3.7
import urllib3
import json
http = urllib3.PoolManager()

def handler(event, context):
  url = "https://hooks.slack.com/services/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"
  msg = {
    "channel": "#devops-remediation-framework",
    "username": "jhon.triana",
    "text": event['Records'][0]['Sns']['Message'],
    "icon_emoji": ":parrot_cop:"
  }

  encoded_msg = json.dumps(msg).encode('utf-8')
  resp = http.request('POST',url, body=encoded_msg)
  print({
    "message": event['Records'][0]['Sns']['Message'],
    "status_code": resp.status,
    "response": resp.data
  })

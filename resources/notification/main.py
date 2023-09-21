#!/usr/bin/python3.7
import urllib3
import json
import os

http = urllib3.PoolManager()


def handler(event, context):
    if os.environ.get("URL_WEB_HOOK", "") != "":
        url = os.environ.get("URL_WEB_HOOK", "")
        msg = {
            "channel": os.environ.get("CHANNEL", ""),
            "username": os.environ.get("USERNAME", ""),
            "text": event['Records'][0]['Sns']['Message'],
            "icon_emoji": ":parrot_cop:"
        }
        encoded_msg = json.dumps(msg).encode('utf-8')
        resp = http.request('POST', url, body=encoded_msg)
        print({
          "message": event['Records'][0]['Sns']['Message'],
          "status_code": resp.status,
          "response": resp.data
        })

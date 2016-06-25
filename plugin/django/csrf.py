from __future__ import absolute_import, division, print_function

import json

import re

from datetime import datetime

import requests

from plugin import client_id, port, server
from plugin.info import send_client_info




class ThreatXSSMiddleware(object):
    def __init__(self, request):
        self.request = request

    def process_request(self):
        query = self.request.META["QUERY_STRING"]
        if xss_strict.search(query):
            url = "http://{0}:{1}/log/new".format(server, port)
            requests.post(url, data={
                "client_id": client_id,
                "timestamp": datetime.utcnow(),
                "data": json.dumps({
                    "event": "CSRF attempt",
                    "url": self.request.path,
                    "query_string": query,
                })
            })

            send_client_info()
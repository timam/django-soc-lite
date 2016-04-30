import json

import re

from datetime import datetime

import requests

from plugin import client_id, port, server
from plugin.info import send_client_info


xss_strict = re.compile("(%3C|<)[^\n]+(%3E|>)")


class ThreatXSSMiddleware(object):
    def process_request(self, request):
        query = request.META["QUERY_STRING"]
        if xss_strict.search(query):
            url = "http://{0}:{1}/log/new".format(server, port)
            requests.post(url, data={
                "client_id": client_id,
                "timestamp": datetime.utcnow(),
                "data": json.dumps({
                    "event": "XSS attempt",
                    "url": request.path,
                    "query_string": query,
                })
            })

            request.session.flush()

        send_client_info()

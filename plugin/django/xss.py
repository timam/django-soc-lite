from __future__ import absolute_import, division, print_function

import json

import re

from datetime import datetime

import requests

from plugin import client_id, port, server
from plugin.info import send_client_info

xss_strict = re.compile("(%3C|<)[^\n]+(%3E|>)")


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
                    "event": "XSS attempt",
                    "url": self.request.path,
                    "query_string": query,
                })
            })

            send_client_info()
            return HtmlEncoding(self.request) ##encoding maliciouscontent to safe format
        else:
            return self.request       ## no malicious content



def HtmlEncoding(maliciouscode):
    htmlCodes = (
        ("'", '&#39;'),
        ('"', '&quot;'),
        ('>', '&gt;'),
        ('<', '&lt;'),
        ('&', '&amp;'),
        ('/', '&#x2F;')
    )
    for code in htmlCodes:
        encoded_html = maliciouscode.replace(code[0], code[1])

    return encoded_html

        
    

from __future__ import absolute_import, division, print_function

import json

import re

from datetime import datetime

import requests

from plugin import client_id, port, server
from plugin.info import send_client_info

xss_strict = re.compile("((%3C|<)[^\n]+(%3E|>))|((%3C|<)/[^\n]+(%3E|>))|(document.)")

def HtmlEncoding(maliciouscode):
    htmlCodes = (
        ("'", '&#39;'),
        ('"', '&quot;'),
        ('>', '&gt;'),
        ('<', '&lt;'),
        ('%3C', '&lt;'),
        ('%3E', '&gt;'),
        ('&', '&amp;'),
        ('/', '&#x2F;'),
        ('document.', 'dom'),
    )
    for code in htmlCodes:
        maliciouscode = maliciouscode.replace(code[0], code[1])

    return maliciouscode

class ThreatXSSMiddleware(object):
    def __init__(self, request, content):
        self.request = request
        self.content = content

    def process_request(self):
        query = self.content
        if xss_strict.search(query):
            url = "http://127.0.0.1:8000/log/new".format(server, port)
            requests.post(url, data={
                "client_id": client_id,
                "timestamp": datetime.utcnow(),
                "data": json.dumps({
                    "event": "XSS attempt",
                    "url": self.request.path,
                    "query_string": query,
                })
            })
            #send_client_info()
            return HtmlEncoding(query) ##encoding maliciouscontent to safe format
        else:
            return query       ## no malicious content





        
    
from __future__ import absolute_import, division, print_function

import email
import email.header
import re
import json
import os
from datetime import datetime



def check_string_for_rfc822_header(s):
          email_header_component = str(email.header.Header('<input>'))
          header_component = (raise_error() if re.search(r'(\r?\n[\S\n\r]|\r[\S\r])', email_header_component) else return email_header_component
          



class ThreatEquationMiddleware(object):
      def __init__(self, message=None, code=None, whitelist=None):
         if message is not None:
            self.message = message
         if code is not None:
            self.code = code
         if whitelist is not None:
            self.whitelist = whitelist

      
       def EmailHeaderInjection(self):    
        if xss_strict.search(self.query):
            url = "http://127.0.0.1:8000/log/new".format(server, port)
            requests.post(url, data={
                "client_id": client_id,
                "timestamp": datetime.utcnow(),
                "data": json.dumps({
                    "event": "XSS attempt",
                    "url": self.request.path,
                    "stacktrace": traceback.format_stack(),
                    "query_string": query,
                })
            })
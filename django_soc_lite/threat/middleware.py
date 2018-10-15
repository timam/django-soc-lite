from __future__ import absolute_import, division, print_function

import json
import re
import requests
import traceback
from django.conf import settings
from django.http import QueryDict, HttpResponse, HttpResponseRedirect, HttpRequest
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote
from plugin.verify import check

class ThreatEquationMiddleware(object):
    def process_request(self, request):
        if check():
            pass
        else:
            return
        self.request = request
        from plugin.threat.xss import XSSMiddleware
        XSSMiddleware(self.request)
        from plugin.threat.sql import SQLMiddleware
        SQLMiddleware(self.request)
        from plugin.threat.directory_traversal import DTMiddleware
        DTMiddleware(self.request)
        
    def process_response(self, request, response):
        if check():
            pass
        else:
            return response
        if getattr(response, 'xframe_options_exempt', False):
            pass  
        else:
            response['X-Frame-Options'] = "DENY"
        response['Server']="n/a"
    
        return response

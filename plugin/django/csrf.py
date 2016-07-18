from __future__ import absolute_import, division, print_function
from django.conf import settings
from plugin import client_id, port, server
from plugin.info import send_client_info
from django.core.urlresolvers import get_callable
from django.utils.cache import patch_vary_headers
from django.utils.hashcompat import md5_constructor
from django.utils.safestring import mark_safe

import requests
import md5
import re
from datetime import datetime

def _make_token(session_id):
    return md5.new(settings.SECRET_KEY + session_id).hexdigest()
    
def detected(request):
    url = "http://{0}:{1}/log/new".format(server, port)
    requests.post(url, data={
        "client_id": client_id,
        "timestamp": datetime.utcnow(),
        "data": json.dumps({
            "event": "CSRF attempt",
            "stacktrace": traceback.format_stack(),
            "url": self.request.path,
            "query_string": query,
        })
    })

    send_client_info()


class CsrfResponseMiddleware(object):
        def process_request(self, request):
        if request.POST:
            try:
                session_id = request.COOKIES[settings.SESSION_COOKIE_NAME]
            except KeyError:
                # No session, no check required
                return 'rejected'
            csrf_token = _make_token(session_id)
            # check incoming token
            try:
                request_csrf_token = request.POST['csrfmiddlewaretoken']
            except KeyError:
                detected(request)
                return 'rejected'
            
            if request_csrf_token != csrf_token:
                detected(request)
                return 'rejected'
                
        return 'rejected'



        

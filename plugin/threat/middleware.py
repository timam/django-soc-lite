from __future__ import absolute_import, division, print_function

import json
import re
import requests
import traceback
from django.conf import settings
#from plugin.info import send_client_info
from django.http import QueryDict, HttpResponse,HttpResponseRedirect,HttpRequest
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote
from plugin.verify import check
from plugin.threat import error_page
class ThreatEquationMiddleware(object):
    #@add_hooks
    #@hook_templates
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
        from plugin.threat.info_disclosure import IDMiddleware
        IDMiddleware(self.request)
        from plugin.threat.local_file_inclusion import LFIMiddleware
        LFIMiddleware(self.request)
        from plugin.threat.remote_file_execution import RFEMiddleware
        RFEMiddleware(self.request)
        from plugin.threat.string_attack import FSMiddleware
        FSMiddleware(self.request)
        
         
        
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
        
        from plugin.threat.debug_fix import Debug_Fix
        Debug_Fix(self.request,response)  
        from plugin.threat.csrf import CSRFMiddleware
        csrf = CSRFMiddleware(request)
        if csrf.check_csrf():
            #from django.middleware.csrf import _get_failure_view
            return HttpResponse(error_page.page_403,status=403)
        from plugin.threat.redirection import RedirectionMiddleware
        redirection = RedirectionMiddleware(request)
        if redirection.get_method():
            response['status_code']=302
            return HttpResponse(error_page.page_302,status=302)
        from plugin.threat.forward import FWDMiddleware
        forward = FWDMiddleware(request)
        #print(settings.MIDDLEWARE_CLASSES)
        #import django
        #print(django.middleware.csrf.get_token(self.request))
        #print(self.request.META['CSRF_COOKIE'])
        #print(self.request.POST.get('csrfmiddlewaretoken', ''))
        if forward.get_method():
            response['status_code']=302
            return HttpResponse("<center><h1>302 Forward Error</h1><p>you are not authorized to see this page</p></center>",status=302)
        
        return response


                       
       
 

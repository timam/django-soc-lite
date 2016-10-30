from __future__ import absolute_import, division, print_function

import json
import re
import requests
import logging
import traceback
from django.conf import settings
#from plugin.info import send_client_info
from django.http import QueryDict, HttpResponse,HttpResponseRedirect
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote 
from plugin.django.logger import log
from plugin.verify import Client_Verify
from plugin.django import error_page
class ThreatEquationMiddleware(object):
    #@add_hooks
    #@hook_templates
    def process_request(self, request):
        import os
        v = Client_Verify(os)
        #print(v.check())
        self.request = request
        
        from plugin.django.xss import XSSMiddleware
        XSSMiddleware(self.request)
        from plugin.django.sql import SQLMiddleware
        SQLMiddleware(self.request)
        from plugin.django.directory_traversal import DTMiddleware
        DTMiddleware(self.request)
        from plugin.django.info_disclosure import IDMiddleware
        IDMiddleware(self.request)
        from plugin.django.local_file_inclusion import LFIMiddleware
        LFIMiddleware(self.request)
        from plugin.django.remote_file_execution import RFEMiddleware
        RFEMiddleware(self.request)
        from plugin.django.string_attack import FSMiddleware
        FSMiddleware(self.request)
        
         
        
    def process_response(self, request, response):
        from plugin.django.csrf import CSRFMiddleware
        csrf = CSRFMiddleware(request)
        if csrf.check_csrf():
            #from django.middleware.csrf import _get_failure_view
            return HttpResponse(error_page.page_403,status=403)
        from plugin.django.redirection import RedirectionMiddleware
        redirection = RedirectionMiddleware(request)
        if redirection.get_method():
            response['status_code']=302
            return HttpResponse(error_page.page_302,status=302)
        from plugin.django.forward import FWDMiddleware
        forward = FWDMiddleware(request)
        #print(settings.MIDDLEWARE_CLASSES)
        #import django
        #print(django.middleware.csrf.get_token(self.request))
        #print(self.request.META['CSRF_COOKIE'])
        #print(self.request.POST.get('csrfmiddlewaretoken', ''))
        if forward.get_method():
            response['status_code']=302
            return HttpResponse("<center><h1>302 Forward Error</h1><p>you are not authorized to see this page</p></center>",status=302)
        if response.get('X-Frame-Options') is not None:
            return response  
        # Don't set it if they used @xframe_options_exempt
        if getattr(response, 'xframe_options_exempt', False):
            return response  
        response['X-Frame-Options'] = self.get_xframe_options_value(request,response)
        return response

    def get_xframe_options_value(self, request, response):
        return getattr(settings, 'X_FRAME_OPTIONS', 'SAMEORIGIN').upper()
    

                       
       
 

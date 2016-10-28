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
"""
def add_hooks(run_hook, get_agent_func=None, timer=None):
    try:
        import django
        import django.conf
    except ImportError:
        return None

    hook_templates(run_hook, timer)

    meta = {
        "version": django.get_version(),
    }

    return meta


def hook_templates(run_hook, timer):
    try:
        import django
    except ImportError:
        return
"""


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
        
        
        #print(self.request.META.get('QUERY_STRING'))RedirectionMiddleware
         
        
    def process_response(self, request, response):
        from plugin.django.redirection import RedirectionMiddleware
        redirection = RedirectionMiddleware(request)
        if redirection.get_method():
            response['status_code']=302
            return HttpResponse("<center><h1>302 Error</h1><p>you are not authorized to see this page</p></center>",status=302)
        from plugin.django.forward import FWDMiddleware
        forward = FWDMiddleware(request)
        #print(settings.MIDDLEWARE_CLASSES)
        print(self.request.COOKIES['csrftoken'])
        print(self.request.method)
        print(self.request.META.get("X-Requested-With"))
        if forward.get_method():
            response['status_code']=302
            return HttpResponse("<center><h1>302 Error</h1><p>you are not authorized to see this page</p></center>",status=302)
        if response.get('X-Frame-Options') is not None:
            return response  
        # Don't set it if they used @xframe_options_exempt
        if getattr(response, 'xframe_options_exempt', False):
            return response  
        response['X-Frame-Options'] = self.get_xframe_options_value(request,response)
        return response

    def get_xframe_options_value(self, request, response):
        return getattr(settings, 'X_FRAME_OPTIONS', 'SAMEORIGIN').upper()
    

    def UnvalidateRedirects(self):
        query = self.request.META.get('QUERY_STRING')
        if not query:
            return False
        q = QueryDict(query)
        dict = q.dict()
        list = [k for k in dict]
        parameter = list[0]
        value = dict[parameter]
        if url_strict.search(str(value)):
            if str(value) != str(self.request.scheme+'://'+self.request.get_host()):
                logging.info(log(event= "redirection attempt", url= self.request.path, stacktrace= traceback.format_stack(), query_string= str(parameter+'='+quote(value))))
                self.request.META['QUERY_STRING']=str(parameter)+'='+str(value)
                return True
        return False
    
    def CSRFMiddleware(self):
        """if self.request.method == 'POST':
            import django
            print(self.request.COOKIES['csrftoken'])
            print(self.request.POST.get("csrfmiddlewaretoken"))
            print(self.request.META.get("X-Requested-With"))
            token = django.middleware.csrf.get_token(self.request)
            print(token)
            try:
                session_id = self.request.COOKIES[settings.SESSION_COOKIE_NAME]
                print(session_id)
            except KeyError:
                # No session, no check required
                print('not auth') 
                #return 'rejected'
            #csrf_token = _make_token(session_id)
            #print(csrf_token)"""
        return False        
                       
       
 

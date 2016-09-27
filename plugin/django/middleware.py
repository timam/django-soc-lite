from __future__ import absolute_import, division, print_function

import json
import re
import requests
import logging
import traceback
from django.conf import settings
from plugin.info import send_client_info
from django.http import QueryDict, HttpResponse
from plugin.HTML_Encode import HTMLEncoding
from plugin.rules import xss_rule, sql_rule
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

xss_strict = re.compile(xss_rule)
sql_strict = re.compile(sql_rule)
rce_strict = re.compile("run()|(p)*open()|delete()|write()|flush()|read(line)*()|call()|system()|format()|getstatus(output)*|communicate()|check_output()")
secure_file_format = re.compile("\.\./[^\r\n]+")       #def FileInjection():
url_strict = re.compile("((http|https|ftp|ftps)\:\/\/)*[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?")



encoding = HTMLEncoding()

class ThreatEquationMiddleware(object):
    #@add_hooks
    #@hook_templates
    def process_request(self, request):
        import os
        v = Client_Verify(os)
        print(v.check())
        self.request = request
        if not self.CSRFMiddleware():
            if not self.XSSMiddleware():
                if not self.INJECTIONMiddleware():
                    if not self.UnvalidateRedirects():
                        pass
        #self.SESSIONMiddleware()
        #self.CSRFMiddleware()
        #self.CSRFMiddleware()
        
    def process_response(self, request, response):
        if response.get('X-Frame-Options') is not None:
            return response  
        # Don't set it if they used @xframe_options_exempt
        if getattr(response, 'xframe_options_exempt', False):
            return response  
        response['X-Frame-Options'] = self.get_xframe_options_value(request,response)
        return response

    def get_xframe_options_value(self, request, response):
        return getattr(settings, 'X_FRAME_OPTIONS', 'SAMEORIGIN').upper()
    
    def XSSMiddleware(self):
        #print(self.request.META.get("HTTP_HOST"))
        #base_url =  "{0}://{1}{2}".format(self.request.scheme, self.request.get_host(), self.request.path)
        #print(base_url)
        if self.request.method == 'GET':
            query = self.request.META.get('QUERY_STRING')
            if not query:
                return False
            q = QueryDict(query)
            dict = q.dict()
            list = [k for k in dict]
            parameter = list[0]
            value = dict[dict.keys()[0]]
        if self.request.method == 'POST':
            self.request.POST = self.request.POST.copy()
            l = [k for k in self.request.POST]
            if not l:
                return False
            parameter = l[0] 
            value = self.request.POST.get(parameter)
        content = value.lower()
        content = content.replace("%20", " ")
        if xss_strict.search(str(content)):
            logging.info(log(event= "XSS attempt", url= self.request.path, stacktrace= traceback.format_stack(), query_string= str(parameter+'='+quote(value))))            
            #send_client_info()
            if self.request.method == 'GET':
                self.request.META['QUERY_STRING']=str(parameter+'='+encoding.XSSEncode(value))
            if self.request.method == 'POST':
                self.request.POST.update({ parameter: encoding.XSSEncode(value)})
            return True
        return False
            
        
    def INJECTIONMiddleware(self):
        def SQLInjection():
            if self.request.method == 'POST':
                self.request.POST = self.request.POST.copy()
                l = [k for k in self.request.POST]
                if not l:
                    return False
                par = l[0] 
                value = self.request.POST.get(par)
            if self.request.method == 'GET':
                query = self.request.META.get('QUERY_STRING')
                if not query:
                    return False 
                q = QueryDict(query)
                dict = q.dict()
                list = [k for k in dict]
                par = list[0]
                value = dict[dict.keys()[0]] 
            content = value.lower()
            content = content.replace("%20", " ") 
        
            if sql_strict.search(content):
                logging.info(log(event= "sql injection attempt", url= self.request.path, stacktrace= traceback.format_stack(), data= value))
                if self.request.method == 'GET':
                    self.request.META['QUERY_STRING']=str(par+'='+sql_strict.sub('',content))
                if self.request.method == 'POST':
                    self.request.POST.update({ par: sql_strict.sub('',content)})
                return True 
            return False             

        def CommandInjection():
            if self.request.method == 'POST':
                self.request.POST = self.request.POST.copy()
                l = [k for k in self.request.POST]
                if not l:
                    return False
                par = l[0] 
                value = self.request.POST.get(par)
            if self.request.method == 'GET':
                query = self.request.META.get('QUERY_STRING')
                if not query:
                    return False 
                q = QueryDict(query)
                dict = q.dict()
                list = [k for k in dict]
                par = list[0]
                value = dict[dict.keys()[0]]
            import base64
            try:
	            b = base64.decodestring(bytes(value, 'ascii'))
	            decoded_string = b.decode("utf-8") 
            except TypeError:
	            try:
		            decoded_string = base64.decodestring(value)
	            except:
	                decoded_string = value	
            if rce_strict.search(str(decoded_string)):
                logging.info(log(event= "command injection attempt", url= self.request.path, stacktrace= traceback.format_stack(), data= value))
                if self.request.method == 'GET':
                    self.request.META['QUERY_STRING']=str(par+'='+'Y29tbWFuZCBhdHRhY2sgZGV0ZWN0ZWQ=')
                if self.request.method == 'POST':
                    self.request.POST.update({ par: 'Y29tbWFuZCBhdHRhY2sgZGV0ZWN0ZWQ='})
                return True 
            return False       

        
        def FileInjection():
            query = self.request.META.get('QUERY_STRING')
            if not query:
                return 
            q = QueryDict(query)
            dict = q.dict()
            list = [k for k in dict]
            parameter = list[0]
            value = dict[dict.keys()[0]]
            
            if secure_file_format.search(str(value)):
                logging.info(log(event= "file injection attempt", url= self.request.path, stacktrace= traceback.format_stack(), data= value))
                self.request.META['QUERY_STRING']=str(parameter)+'='+str(encoding.FileInjectionEncode(value))    
                return True
            
            
        if not SQLInjection():
            if not CommandInjection():
                FileInjection()


    def UnvalidateRedirects(self):
        query = self.request.META.get('QUERY_STRING')
        if not query:
            return False
        q = QueryDict(query)
        dict = q.dict()
        list = [k for k in dict]
        parameter = list[0]
        value = dict[dict.keys()[0]]
        if url_strict.search(str(value)):
            if str(value) != str(self.request.scheme+'://'+self.request.get_host()):
                logging.info(log(event= "redirection attempt", url= self.request.path, stacktrace= traceback.format_stack(), query_string= str(parameter+'='+quote(value))))
                self.request.META['QUERY_STRING']=str(parameter)+'='+"{0}://{1}".format(self.request.scheme, self.request.get_host())
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
                       
       
 

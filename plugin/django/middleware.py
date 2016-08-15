from __future__ import absolute_import, division, print_function

import json
import re
import requests

from datetime import datetime
from plugin import client_id, port, server
from plugin.info import send_client_info
from django.http import QueryDict, HttpResponse
from plugin.HTML_Encode import HTMLEncoding
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
xss_strict = re.compile("((%3C|<)[^\n]+(%3E|>))|((%3C|<)/[^\n]+(%3E|>))|(document.)")
sql_strict = re.compile("(\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52)))|((\%3D)|(=)|(>)|(<))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))|(;(\s\w+)+|;|--;|;--)")
rce_strict = re.compile("run()|(p)*open()|delete()|write()|flush()|read(line)*()|call()|system()|format()|getstatus(output)*|communicate()|check_output()")
secure_file_format = re.compile("\.\./[^\r\n]+")       #def FileInjection():
url_strict = re.compile("(http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?")



encoding = HTMLEncoding()

class ThreatEquationMiddleware(object):

    #@add_hooks
    #@hook_templates
    def process_request(self, request):
        self.request = request
        self.XSSMiddleware()
        self.INJECTIONMiddleware()
        self.UnvalidateRedirects()
        #self.SESSIONMiddleware()
        #self.CSRFMiddleware()
        #self.CSRFMiddleware()
        
        
    def XSSMiddleware(self):
        query = self.request.META.get('QUERY_STRING')
        if not query:
            return 
        q = QueryDict(query)
        dict = q.dict()
        list = [k for k in dict]
        parameter = list[0]
        value = dict[dict.keys()[0]]
        if xss_strict.search(str(value)):
            """
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
            """    
            #send_client_info()
            self.request.META['QUERY_STRING']=str(parameter+'='+encoding.XSSEncode(value))
        
    def INJECTIONMiddleware(self):
        def SQLInjection():
            self.request.POST = self.request.POST.copy()
            l = [k for k in self.request.POST]
            if not l:
                return False
            par = l[0] 
            value = self.request.POST.get(par)
            # perform operation on value
            if sql_strict.search(str(value)):
                self.request.POST.update({ par: 'sql attack detected' })
                return True

        def CommandInjection():
            self.request.POST = self.request.POST.copy()
            l = [k for k in self.request.POST]
            if not l:
                return False
            par = l[0] 
            value = self.request.POST.get(par)
            print(par,value)
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
                self.request.POST.update({ par: 'Y29tbWFuZCBhdHRhY2sgZGV0ZWN0ZWQ=' })
                return True

        
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
                """
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
                """
                self.request.META['QUERY_STRING']=str(parameter)+'='+str(encoding.FileInjectionEncode(value))    
                return True
            
            
        if not SQLInjection():
            if not CommandInjection():
                FileInjection()


    def UnvalidateRedirects(self):
        #print(self.request.META['SERVER_NAME'])
        url = self.request.META.get('QUERY_STRING')
        if not url:
            return 
        q = QueryDict(url)
        dict = q.dict()
        list = [k for k in dict]
        parameter = list[0]
        value = dict[dict.keys()[0]]
        if url_strict.search(str(value)):
            m = re.search('(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*',str(value))
            if m.group('host') != self.request.META.get('REMOTE_ADDR'):
                self.request.META['QUERY_STRING']=str(parameter)+'='+str('http://'+self.request.META['HTTP_HOST'])
            return
        return
                
       
 

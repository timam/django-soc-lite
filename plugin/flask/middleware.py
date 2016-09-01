from flask import session,request
from plugin import client_id, port, flask_server
from plugin.flask.compat import iteritems
from plugin.HTML_Encode import HTMLEncoding

from datetime import datetime
import requests
import re
import traceback
import json
import sys 

server = flask_server

xss_strict = re.compile("((%3C|<)[^\n]+(%3E|>))|((%3C|<)/[^\n]+(%3E|>))|(document.)|alert()|onclick()")
sql_strict = re.compile("(\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52)))|((\%3D)|(=)|(>)|(<))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))|(;(\s\w+)+|;|--;|;--)")
rce_strict = re.compile("run()|(p)*open()|delete()|write()|flush()|read(line)*()|call()|system()|format()|getstatus(output)*|communicate()|check_output()")
secure_file_format = re.compile("\.\./[^\r\n]+")       #def FileInjection():
url_strict = re.compile("(http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?")


encoding = HTMLEncoding()

class ThreatEquationMiddleware(object):

    def __init__(self,app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app): 
        for k, v in iteritems(self._default_config(app)):
            app.config.setdefault(k, v)
          
        app.before_request(self.process_request)
        app.after_request(self.process_response)
 
    def _default_config(self, app):
        return {
            'DEBUG_TB_HOSTS': (),
        }
       
    def process_request(self):
        if not self.XSSMiddleware():
            if not self.INJECTIONMiddleware():
                if not self.UnvalidateRedirects():
                    pass 
        #self.CSRFMiddleware()
        #self.SESSIONMiddleware()
        #self.CSRFMiddleware()
        #self.CSRFMiddleware()
    
    def XSSMiddleware(self):
        if request.method == 'POST':
            request.form = request.form.copy()
            l = [k for k in request.form]
            if not l:
                return
            par = l[0] 
            value = request.form.get(par)
        if request.method == 'GET':
            request.args = request.args.copy()
            l = [k for k in request.args]
            if not l:
                return False 
            par = l[0]
            value = request.args.get(par)
        if xss_strict.search(str(value)):
            url = server
            requests.post(url, data={
                "client_id": client_id,
                "timestamp": datetime.utcnow(),
                "data": json.dumps({
                    "event": "XSS attempt",
                    "url": request.path,
                    "stacktrace": traceback.format_stack(),
                    "query_string": par+'='+value,
                })
            })
            if request.method == 'POST':
                request.form[par]=str(encoding.XSSEncode(value))
            if request.method == 'GET':
                request.args[par]=str(encoding.XSSEncode(value))
            return True 
        else:
            return False
                
    def INJECTIONMiddleware(self):
        def SQLInjection():
            if request.method == 'POST':
                request.form = request.form.copy()
                l = [k for k in request.form]
                if not l:
                    return False
                par = l[0] 
                value = request.form.get(par)
            if request.method == 'GET':
                request.args = request.args.copy()
                l = [k for k in request.args]
                if not l:
                    return False 
                par = l[0]
                value = request.args.get(par)
            
            # perform operation on value
            if sql_strict.search(str(value)):
                url = server
                requests.post(url, data={
                    "client_id": client_id,
                    "timestamp": datetime.utcnow(),
                    "data": json.dumps({
                        "event": "sql attempt",
                        "url": request.path,
                        "stacktrace": traceback.format_stack(),
                        "query_string": par+'='+value,
                    })
                })
                if request.method == 'POST':
                    request.form[par]=str('sql attack detected')
                if request.method == 'GET':
                    request.args[par]=str('null') 
                    
                return True

        def CommandInjection():
            if request.method == 'POST':
                request.form = request.form.copy()
                l = [k for k in request.form]
                if not l:
                    return False
                par = l[0] 
                value = request.form.get(par)
            if request.method == 'GET':
                request.args = request.args.copy()
                l = [k for k in request.args]
                if not l:
                    return False 
                par = l[0]
                value = request.args.get(par)
            #print(par,value)
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
                url = server
                requests.post(url, data={
                    "client_id": client_id,
                    "timestamp": datetime.utcnow(),
                    "data": json.dumps({
                        "event": "os command attempt",
                        "url": request.path,
                        "stacktrace": traceback.format_stack(),
                        "query_string": par+'='+value,
                    })
                })
                if request.method == 'POST':
                    request.form[par]=str('Y29tbWFuZCBhdHRhY2sgZGV0ZWN0ZWQ=')
                if request.method == 'GET':
                    request.args[par]=str('Y29tbWFuZCBhdHRhY2sgZGV0ZWN0ZWQ=') 
                return True

        
        def FileInjection():
            if request.method == 'POST':
                request.form = request.form.copy()
                l = [k for k in request.form]
                if not l:
                    return False
                par = l[0] 
                value = request.form.get(par)
            if request.method == 'GET':
                request.args = request.args.copy()
                l = [k for k in request.args]
                if not l:
                    return False 
                par = l[0]
                value = request.args.get(par)
            
            if secure_file_format.search(str(value)):
                url = server
                requests.post(url, data={
                    "client_id": client_id,
                    "timestamp": datetime.utcnow(),
                    "data": json.dumps({
                        "event": "file attempt",
                        "url": request.path,
                        "stacktrace": traceback.format_stack(),
                        "query_string": query,
                    })
                })
                if request.method == 'POST':
                    request.form[par]=str(encoding.FileInjectionEncode(value))
                if request.method == 'GET':
                    request.args[par]=str(encoding.FileInjectionEncode(value))
                return True
            
            
        if not SQLInjection():
            if not CommandInjection():
                if FileInjection():
                    return True
                else:
                    return False 
   
    def UnvalidateRedirects(self):
        request.args = request.args.copy()
        l = [k for k in request.args]
        if not l:
            return False 
        par = l[0]
        value = request.args.get(par)
        if url_strict.search(str(value)):
            m = re.search('(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*',str(value))
            if m.group('host') != request.environ.get('REMOTE_ADDR'):
                url = server
                requests.post(url, data={
                    "client_id": client_id,
                    "timestamp": datetime.utcnow(),
                    "data": json.dumps({
                        "event": "rediretion attempt",
                        "url": request.path,
                        "stacktrace": traceback.format_stack(),
                        "query_string": url,
                    })
                })
                request.args[par]=str('http://'+request.environ['HTTP_HOST'])
                return True
            return False

    def process_response(self, response):
        headers = response.headers
        headers['X-Frame-Options'] = 'SAMEORIGIN'

        return response
    
   
 
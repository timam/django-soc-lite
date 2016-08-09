from flask import session,request
from plugin.flask.compat import iteritems
from plugin.HTML_Encode import HTMLEncoding
import requests
import re


xss_strict = re.compile("((%3C|<)[^\n]+(%3E|>))|((%3C|<)/[^\n]+(%3E|>))|(document.)")
secure_file_format = re.compile("(.)*/(?:$|(.+?)(?:(\.[^.]*$)|$))")       #def FileInjection():

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
        self.XSSMiddleware()
        #self.INJECTIONMiddleware()
        #self.CSRFMiddleware()
        #self.SESSIONMiddleware()
        #self.CSRFMiddleware()
        #self.CSRFMiddleware()
    
    def XSSMiddleware(self):
        request.args = request.args.copy()
        l = [k for k in request.args]
        if not l:
            return 
        par = l[0] 
        value = request.args.get(par)
        if xss_strict.search(str(value)):
            request.args[par]=str(encoding.XSSEncode(value))
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

    def process_response(self, response):
        headers = response.headers
        headers['X-Frame-Options'] = 'SAMEORIGIN'

        return response
    
   
 

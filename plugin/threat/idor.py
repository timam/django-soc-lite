from plugin.threat.middleware import *
from plugin import url_coder
from plugin.threat.log_generator import send
def send_log(request, query):
    send(request, "IDOR", str(query), traceback.format_stack(), request.path)
    

class IDORMiddleware(object):
    def __init__(self, request):
        self.request = request
        if self.request.method == 'GET':
            self.get_method()

    def get_method(self):
        query = self.request.META.get('QUERY_STRING')
        if query:
            q = QueryDict(query)
            dict = q.dict()
            list = [k for k in dict]
            parameter = list[0]
            org_value = dict[parameter]
            value = url_coder.decoder(str(org_value))                    #decoding/double/decoding
            if rule_checker.xss_filter(str(value)):                      #check attack 
                #print('don')
                send_log(self.request, query)
                q = bleach.clean(value)
                if not isinstance(q, str):
                    q = q.encode("utf-8")
 
                q = HTML_Escape.XSSEncode(q)
                #print(q)                    
                self.request.META['QUERY_STRING']=str(parameter+'='+q)
                return True
            return False
        if not query:
            try:
                path = self.request.path
                import os.path                                    
                org_value = os.path.split(path)[1]                         #last value from path
                value = url_coder.decoder(str(org_value))                   #decoding/double/decoding
                if rule_checker.xss_filter(str(value)):                #check attack
                    send_log(self.request, org_value)
                    q = bleach.clean(value)
                    if not isinstance(q, str):
                        q = q.encode("utf-8")
 
                    q = HTML_Escape.XSSEncode(q)   
                self.request.path_info = os.path.join(os.path.split(path)[0],q)            #update path
                return True
            except:
                return False 

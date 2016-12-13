from plugin.threat.middleware import *
import bleach
from plugin import url_coder, rule_checker, HTML_Escape
from plugin.threat.log_generator import send
def send_log(request, query):
    send(request, "ID", str(query), traceback.format_stack(), request.path,'medium')

class IDMiddleware(object):
    def __init__(self, request):
        self.request = request
        if self.request.method == 'GET':
            self.get_method()
        if self.request.method == 'POST':
            self.post_method()

    def get_method(self):
        query = self.request.META.get('QUERY_STRING')
        if query:
            q = QueryDict(query)
            dict = q.dict()
            list = [k for k in dict]
            parameter = list[0]
            value = dict[parameter]
            value = url_coder.decoder(str(value))                          #decoding/double/decoding
            if rule_checker.id_filter(str(value)):                         #check attack 
                send_log(self.request, query)
                q = bleach.clean(value)
                
                q = HTML_Escape.CommandEscape(q)  
                if not isinstance(q, str):
                    q = q.encode("utf-8")
                
                self.request.META['QUERY_STRING']=str(parameter+'='+q)
                return True
            return False
        if not query:
            try:
                path = self.request.path
                import os.path                                    
                org_value = os.path.split(path)[1]                        #last value from path
                value = url_coder.decoder(str(org_value))                  #decoding/double/decoding
                if rule_checker.id_filter(str(value)):                #check attack
                    send_log(self.request, org_value)
                    q = bleach.clean(value)
                    if not isinstance(q, str):
                        q = q.encode("utf-8")
 
                    q = HTML_Escape.CommandEscape(q)
                self.request.path_info = os.path.join(os.path.split(path)[0],q)            #update path
                return True
            except:
                return False 
    def post_method(self):
        self.request.POST = self.request.POST.copy()
        l = [k for k in self.request.POST]
        if not l:
            return
        for i in range(len(l)):
            par = l[i] 
            org_value = self.request.POST.get(par)
            value = url_coder.decoder(str(org_value))
            if rule_checker.id_filter(str(value)): 
                send_log(self.request, str(par+'='+org_value))
                q = bleach.clean(value)
                if not isinstance(q, str):
                    q = q.encode("utf-8")
                q = HTML_Escape.CommandEscape(q)
                self.request.POST.update({ par: q}) 





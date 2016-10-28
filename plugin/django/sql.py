from plugin.django.middleware import *
import bleach

from plugin import url_coder, rule_checker, HTML_Escape

def checker(q):
    #logging.info(log(event= "XSS attempt", url= self.request.path, stacktrace= traceback.format_stack(), query_string= str(parameter+'='+quote(value))))
    q = bleach.clean(q)
    if not isinstance(q, str):
        q = q.encode("utf-8")
    #q = HTML_Escape.XSSEncode(q)                    
    return q
    
    

class SQLMiddleware(object):
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
            if rule_checker.sql_filter(str(value)):                  #check attack 
                q = checker(value)
                q = rule_checker.sql_replace(q) 
                self.request.META['QUERY_STRING']=str(parameter+'='+q)
        return

    def post_method(self):
        self.request.POST = self.request.POST.copy()
        l = [k for k in self.request.POST]
        if not l:
            return
        for i in range(len(l)):
            par = l[i] 
            value = self.request.POST.get(par).lower()
            value = url_coder.decoder(str(value))
            if rule_checker.sql_filter(str(value)): 
                value = checker(value)
                #print('sql')
                q = rule_checker.sql_replace(value) 
                self.request.POST.update({ par: q}) 
            




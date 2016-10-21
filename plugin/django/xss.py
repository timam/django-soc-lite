from plugin.django.middleware import *
from plugin.rules import xss_rule
import bleach

from plugin import url_coder
xss_strict = re.compile(xss_rule)

class XSSMiddleware1(object):
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
            if xss_strict.search(value):                  #check attack 
                #logging.info(log(event= "XSS attempt", url= self.request.path, stacktrace= traceback.format_stack(), query_string= str(parameter+'='+quote(value))))
                q = bleach.clean(value)
                print('detected')  
                #if not isinstance(q, str):
                    #q = q.encode("utf-8")
                
                self.request.META['QUERY_STRING']=str(parameter+'='+q)
                return True
            return False
        if not query:
            try:
                path = self.request.path
                import os.path                                    
                value = os.path.split(path)[1]                         #last value from path
                path = url_coder.decoder(value)                        #decoding/double/decoding
                #check attack       
                #self.request.path_info = '/injection'            #update path
                return True
            except:
                return False  
    def post_method(self):
        print(self.request +'post_m')






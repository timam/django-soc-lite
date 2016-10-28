from plugin.django.middleware import *
from django.template import RequestContext,Template,loader
from django.http import HttpResponse
from plugin import url_coder

def logger(q):
    #logging.info(log(event= "XSS attempt", url= self.request.path, stacktrace= traceback.format_stack(), query_string= str(parameter+'='+quote(value))))
    pass
    
    

class FWDMiddleware(object):
    def __init__(self, request):
        self.request = request

    def get_method(self):
        if self.request.method == 'GET':
            query = self.request.META.get('QUERY_STRING')
            if query:
                q = QueryDict(query)
                dict = q.dict()
                list = [k for k in dict]
                parameter = list[0]
                if parameter=='fwd' or parameter=='forward' :                  #check attack 
                  logger(str(query)) 
                  return True
            return None
        return None



             

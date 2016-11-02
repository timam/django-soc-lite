from plugin.django.middleware import *
from django.template import RequestContext,Template,loader
from django.http import HttpResponse
from plugin import url_coder

import logging
from plugin.django.logger import log
def send_log(request, query):
    logging.info(log(event= "unvalidate forward attempt", url= request.path, stacktrace= traceback.format_stack(), query_string= str(query)))
    #print(str(query))    

class FWDMiddleware(object):
    def __init__(self, request):
        self.request = request

    def get_method(self):
        if self.request.method == 'GET':
            query = self.request.META.get('QUERY_STRING')
            query = url_coder.decoder(str(query))        
            if query:
                q = QueryDict(query)
                dict = q.dict()
                list = [k for k in dict]
                parameter = list[0]
                if parameter=='fwd' or parameter=='action' :                  #check attack 
                  send_log(self.request,query)
                  return True
            return None
        return None



             

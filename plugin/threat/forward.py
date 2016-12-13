from plugin.threat.middleware import *
from django.template import RequestContext,Template,loader
from django.http import HttpResponse
from plugin import url_coder

from plugin.django.log_generator import send
def send_log(request, query):
    send(request, "UF", str(query), traceback.format_stack(), request.path)

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



             

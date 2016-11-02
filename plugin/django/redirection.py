from plugin.django.middleware import *
from plugin import url_coder
import logging
from plugin.django.logger import log
def send_log(request, query):
    logging.info(log(event= "unvalidate redirection attempt", url= request.path, stacktrace= traceback.format_stack(), query_string= str(query)))
    #print(str(query))
    
    

class RedirectionMiddleware(object):
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
                p_list = ['url','next']
                if parameter in p_list:
                    value = dict[parameter]
                    value = url_coder.decoder(str(value))
                    try:
                        host_whitelist = settings.ALLOWED_HOST           #check ALLOWED_host from app settings file
                    except AttributeError:
                        host_whitelist = ('',)
                    if value in host_whitelist:
                        return False
                    send_log(self.request, query)
                    return True
            return None
        return None



             

from plugin.django.middleware import *
from django.template import RequestContext,Template,loader

def logger(req):
    #logging.info(log(event= "csrf attempt", url= self.request.path, stacktrace= traceback.format_stack(), query_string= str(parameter+'='+quote(value))))
    pass
    
    

class CSRFMiddleware(object):
    def __init__(self, request):
        self.request = request

    def check_csrf(self):
        if self.request.method == 'POST':
            import django
            print(self.request.META['CSRF_COOKIE']) 
            session_id = django.middleware.csrf.get_token(self.request)
            request_cookie = self.request.POST.get('csrfmiddlewaretoken') 
            print(session_id, request_cookie)
            if request_cookie is None:
                logger(self.request)
                return True
            return False

        return False



             

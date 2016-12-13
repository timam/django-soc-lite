from plugin.threat.middleware import *
from django.template import RequestContext,Template,loader
from plugin.threat.log_generator import send
def send_log(request, query):
    send(request, "CSRF", str(query), traceback.format_stack(), request.path)
        
class CSRFMiddleware(object):
    def __init__(self, request):
        self.request = request

    def check_csrf(self):
        if self.request.method == 'POST':
            import django
            #print(self.request.META['CSRF_COOKIE']) 
            #session_id = django.middleware.csrf.get_token(self.request)
            request_cookie = self.request.POST.get('csrfmiddlewaretoken') 
            #print(session_id, request_cookie)
            if request_cookie is None:
                send_log(self.request)
                return True
            return False

        return False



             

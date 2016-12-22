from plugin.threat.middleware import *
from django.conf import settings
    
class Debug_Fix(object):
    def __init__(self,request,response):
        self.request = request
        self.response = response
        self.check_method()

    def check_method(self):
        if hasattr(settings, 'ALLOWED_HOSTS'):
            if len(settings.ALLOWED_HOSTS)==0:
                #print(self.request.META['HTTP_HOST'])
                settings.ALLOWED_HOSTS += '*'
            if settings.DEBUG==True:
                settings.DEBUG=False
    
        else: 
            settings.configure(ALLOWED_HOSTS=['*'])
            if settings.DEBUG==True:
                settings.DEBUG=False
        
         
        




from django.conf import settings
from datetime import datetime
from plugin import client_id, port, server
from plugin.info import send_client_info
from urlparse import urlparse, urljoin

import json
import requests

_ALLOWED_HOST = settings.ALLOWED_HOSTS    #determinr allowed host list from app

class ThreatRedirectAndForward(object):
    def Redirect(self,request):
        url = request.GET.get('url')
        target_url = urlparse(url)
        if target_url.netloc not in _ALLOWED_HOST:
            detected(request,url)
            return False
            
        rteurn True
        
    def Forward(self,request):
        pass
    
def detected(request,query):
    url = "http://{0}:{1}/log/new".format(server, port)
    requests.post(url, data={
        "client_id": client_id,
        "timestamp": datetime.utcnow(),
        "data": json.dumps({
        "event": " unvalidated redirects & forwards attempt",
            "url": self.request.path,
            "query_string": query,
        })
    })
    send_client_info()

    
  
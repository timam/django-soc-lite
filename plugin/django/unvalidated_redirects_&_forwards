from datetime import datetime
from plugin import client_id, port, server
from plugin.info import send_client_info

import json
import requests

_ALLOWED_HOST = '' #determinr allowed host list from app

class ThreatRedirect&Forward(object):
    def Redirect(self,request):
        url = request.GET.get('url')
        if not _ALLOWED_HOST.match(url):
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
        "event": "SQL attempt",
            "url": self.request.path,
            "query_string": query,
        })
    })
    send_client_info()

    
  
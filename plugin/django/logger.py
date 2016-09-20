import json
import logging
import requests
from datetime import datetime
from plugin import client_id, port, django_server

class StructuredMessage(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs 

    def __str__(self):
    	data = {"client_id":str(client_id),"timestamp":str(datetime.utcnow()),"data":json.dumps(self.kwargs)}
        requests.post(django_server, data)
        
        return json.dumps(self.kwargs)

log = StructuredMessage   # optional, to improve readability

logging.basicConfig(level=logging.INFO, format='%(message)s')

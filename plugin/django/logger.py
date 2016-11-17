import json
import logging
import requests
from plugin import port, django_server

class StructuredMessage(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        #print(type(self.kwargs),self.kwargs)
        #print(type(json.dumps(self.kwargs)),json.dumps(self.kwargs))
        #print(type(json.dumps(json.dumps(self.kwargs))),json.dumps(json.dumps(self.kwargs))) 
        r = requests.post(django_server, headers={'Content-Type': 'application/json'}, data=json.dumps(self.kwargs))
        #print(r.text)
        
    def __str__(self):
        return json.dumps(self.kwargs)

log = StructuredMessage   # optional, to improve readability
logging.basicConfig(level=logging.INFO, format='%(message)s')

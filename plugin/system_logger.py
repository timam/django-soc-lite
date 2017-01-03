import json
import logging
import requests
from plugin import port, system_log_server

class StructuredMessage(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        #print(type(self.kwargs),self.kwargs)
        #print(type(json.dumps(self.kwargs)),json.dumps(self.kwargs))
        #r = requests.post(system_log_server, headers={'Content-Type': 'application/json'}, json={"data":self.kwargs})
        
    def __str__(self):
        return json.dumps(self.kwargs)

log = StructuredMessage   # optional, to improve readability
logging.basicConfig(level=logging.INFO, format='%(message)s')

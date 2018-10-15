import json
import logging
import requests
from plugin import port, django_server, library_log_server, system_log_server

class StructuredMessage(object):
    def __init__(self, name, **kwargs):
        self.name = name
        self.kwargs = kwargs
        print(type(self.kwargs),self.kwargs)
        #print(type(json.dumps(self.kwargs)),json.dumps(self.kwargs))
        if self.name == 'attack':
            requests.post(django_server, headers={'Content-Type': 'application/json'}, json={"data":self.kwargs})
        if self.name == 'library':
            requests.post(library_log_server, headers={'Content-Type': 'application/json'}, json={"data":self.kwargs})
        #if self.name == 'system':
            #requests.post(system_log_server, headers={'Content-Type': 'application/json'}, json={"data":self.kwargs})
    def __str__(self):
        return json.dumps(self.kwargs)

log = StructuredMessage   # optional, to improve readability
logging.basicConfig(level=logging.INFO, format='%(message)s')

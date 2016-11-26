from plugin import location, client_id, secret, verify_url
import requests
import json
    
def verify(k, s):
    data = {"id": str(k), "secret": str(s)}
    r = requests.post(verify_url, headers={'Content-Type': 'application/json'}, data = json.dumps(data))
    if str(r.text) == 'y':
        return True
    else:
        return False 
  
def check():
    if client_id == 'n/a' or secret == 'n/a':
        return False
       
    return True



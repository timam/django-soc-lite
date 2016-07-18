from django.db import connection
from datetime import datetime
from plugin import client_id, port, server
from plugin.info import send_client_info

import json
import requests
import re

secure_file_format = re.compile("(.)*/(?:$|(.+?)(?:(\.[^.]*$)|$))")
def HtmlEncoding(path):
    htmlCodes = (
        (".", ''),
        (' &#183;', ''),
        ('/', ''),
        ('&#47;', ''), 
    )
    for code in htmlCodes:
        path = path.replace(code[0], code[1])

    return path
    
class ThreatSqlInjection(object):
    def SqlInjection(self,request):
        user = request.GET['username']
        sql = "SELECT * FROM user_contacts WHERE username = %s"
        cursor = connection.cursor()
        c = connection.cursor()
        
        try:
            c.execute(sql, [user])   
        finally:
            c.close()
            
    def InsecureFileAccess(self,request):
        query = request.GET.get('filename')
        if secure_file_format.search(query):
            detected(request,query)
            return HtmlEncoding(query)
        return query    
        
    
def detected(request,query):
    url = "http://{0}:{1}/log/new".format(server, port)
    requests.post(url, data={
        "client_id": client_id,
        "timestamp": datetime.utcnow(),
        "data": json.dumps({
            "event": "SQL attempt",
            "url": self.request.path,
            "stacktrace": traceback.format_stack(),
            "query_string": query,
        })
    })
    send_client_info()

    
  
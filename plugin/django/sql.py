from django.db import connection
from datetime import datetime
from plugin import client_id, port, server
from plugin.info import send_client_info

import json
import requests
import re


def SqlInjection(request):
    user = request.GET['username']
    sql = "SELECT * FROM user_contacts WHERE username = %s"
    cursor = connection.cursor()
    c = connection.cursor()
try:
    c.execute(sql, [user])
finally:
    c.close()
    
def detected(request):
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
  
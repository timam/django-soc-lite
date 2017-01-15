import json
import logging
from datetime import datetime
from plugin.logger import log
from plugin import client_id, plugin_name

IP_LIST = (
    'HTTP_CF_CONNECTING_IP',
    'HTTP_X_FORWARDED_FOR', 
    'HTTP_CLIENT_IP',
    'HTTP_X_REAL_IP',
    'HTTP_X_FORWARDED',
    'HTTP_X_CLUSTER_CLIENT_IP',
    'HTTP_FORWARDED_FOR',
    'HTTP_FORWARDED',
    'HTTP_VIA',
    'REMOTE_ADDR',
)


def send(request, event, queryString, stacktrace, url, d_method='input validation' risk='high', description='strong attack',impact='high risk',cwe='190'):
    userAgent = request.META['HTTP_USER_AGENT']
    for i in IP_LIST:
        if request.META.get(str(i)):
            ip = request.META.get(str(i))
            break
        
    if ip:
        pass
    else:
       ip = 'unknown'
    import sys
    import django
    from django.db import connection
    db_name = connection.vendor
    agent = 'Django'+' : '+django.get_version()
    core = 'Python'+' : '+'{0[0]}.{0[1]}.{0[2]}'.format(sys.version_info)
    version = {'core':core,'agent':agent,'database':db_name}
    internal_data = {'decription':description, 'impact':impact, 'cwe':cwe, 'method':request.method, 'event':event, 'queryString':queryString, 'risk':risk,'url':url, 'stacktrace':stacktrace}
    logging.info(log(name='attack',clientId=client_id, ip=ip, userAgent=userAgent, timestamp=str(datetime.utcnow()),ApplicationName=plugin_name, data=internal_data,backend=version,defence_method=d_method))
    
    








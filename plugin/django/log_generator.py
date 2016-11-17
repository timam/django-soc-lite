import json
import logging
from datetime import datetime
from plugin.django.logger import log
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


def send(request, event, queryString, stacktrace, url, risk='n'):
    userAgent = request.META['HTTP_USER_AGENT']
    for i in IP_LIST:
        if request.META.get(str(i)):
            ip = request.META.get(str(i))
            break
        
    if ip:
        pass
    else:
       ip = 'unknown'
    internal_data = {'event':event,'queryString':queryString,'risk':risk,'url':url,'stacktrace':stacktrace}
    logging.info(log(clientId=client_id, ip=ip, userAgent=userAgent, timestamp=str(datetime.utcnow()),ApplicationName=plugin_name, data=internal_data))
    
    







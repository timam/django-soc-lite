from __future__ import absolute_import, division, print_function

import os
location = os.path.expanduser("~")
try:
    filename = os.path.join(location, 'threat.ini')
    with open(filename, "r") as ins:
        array = []
        for line in ins:
            line = line.rstrip('\n').rstrip('\r') 
            array.append(line) 
    for i in range(len(array)):
        array[i] = array[i].replace(" ", "")
        array[i] = array[i].split("=")

    client_id = array[0][1]
    secret = array[1][1]    
except IOError as exc:
    client_id = 'n/a'
    secret = 'n/a'

plugin_name = 'ThreatequationPythonDjango v0.0.3'
django_server = 'http://testapi.threatequation.com/'
library_log_server = 'http://testapi.threatequation.com/library/'
system_log_server = 'http://testapi.threatequation.com/system/'
verify_url = 'http://api.threatequation.com/verify'
server = ''
port = None

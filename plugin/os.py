from datetime import datetime
import os
import re
import traceback
import json

import requests

from shellescape import quote


__implements__ = ["system"]
_find_potential_attacks = re.compile(r"[;$`|&><-]").search

_system = os.system

app_directory = os.path.join(os.path.expanduser("~"), ".plugin")

with open(os.path.join(app_directory, "client_id")) as f:
    client_id = f.read()

def system(command):
    if _find_potential_attacks(command) is not None:
        requests.post("http://localhost:4040/log/new", data={
            "client_id": client_id,
            "timestamp": datetime.utcnow(),
            "data": json.dumps({
                "event": "injection attempt",
                "stacktrace": traceback.format_stack(),
                "data": command,
            })
        })

    return _system(quote(command))

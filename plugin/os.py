import json
import os
import re
import traceback

from datetime import datetime

import requests

from shellescape import quote

from plugin import client_id


__implements__ = ["system"]
_find_potential_attacks = re.compile(r"[;$`|&><-]").search

_system = os.system


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

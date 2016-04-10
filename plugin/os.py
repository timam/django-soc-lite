import json
import os
import re
import traceback

from datetime import datetime

import requests

from shellescape import quote

from plugin import client_id, port, server
from plugin.info import send_client_info


__implements__ = ["system"]
_find_potential_attacks = re.compile(r"[;$`|&><-]").search

_system = os.system


def system(command):
    if _find_potential_attacks(command) is not None:
        requests.post("http://{0}:{1}/log/new".format(server, port), data={
            "client_id": client_id,
            "timestamp": datetime.utcnow(),
            "data": json.dumps({
                "event": "injection attempt",
                "stacktrace": traceback.format_stack(),
                "data": command,
            })
        })

    send_client_info()

    return _system(quote(command))

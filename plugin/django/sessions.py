import json

from datetime import datetime

import requests

from plugin import client_id, port, server
from plugin.info import send_client_info


class ThreatSessionMiddleware(object):
    def process_request(self, request):
        try:
            fingerprint = request.session["THREAT_FINGERPRINT"]
        except KeyError:
            fingerprint = request.META["HTTP_USER_AGENT"]
            request.session["THREAT_FINGERPRINT"] = fingerprint
            request.session.save()
        else:
            if fingerprint != request.META["HTTP_USER_AGENT"]:
                url = "http://{0}:{1}/log/new".format(server, port)
                requests.post(url, data={
                    "client_id": client_id,
                    "timestamp": datetime.utcnow(),
                    "data": json.dumps({
                        "event": "session attempt",
                        "session_info": request.COOKIES
                    })
                })

                request.session.flush()

        send_client_info()

from __future__ import unicode_literals

import datetime
import re

class ThreatClickjackingMiddleware(object):
       def after_request(self, registry):
          def clickjacking(request):
              settings, response = registry.settings, request.response
              HEADER = 'X-Frame-Options'
              if not response.headers.get(HEADER, None):
                 option = settings.get('x_frame_options', 'DENY').upper()
                 response.headers[HEADER] = option
              return handler(request)
           return clickjacking
         
           def detected(request):
               url = "http://{0}:{1}/log/new".format(server, port)
               requests.post(url, data={
                     "client_id": client_id,
                     "timestamp": datetime.utcnow(),
                     "data": json.dumps({
                     "event": "CSRF attempt",
                     "stacktrace": traceback.format_stack(),
                     "url": self.request.path,
                     "query_string": query,
                    })
                  })

            send_client_info()  

    
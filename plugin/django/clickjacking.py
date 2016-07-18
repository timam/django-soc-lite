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


    
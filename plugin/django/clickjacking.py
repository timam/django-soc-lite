from __future__ import unicode_literals

import datetime
import re

class ThreatClickjackingMiddleware(object):
      def check(request):
          if isinstance(request, HTTPRequest):
             if request.get('REQUEST_METHOD', 'GET').upper() != 'POST':
                raise Forbidden('Request must be POST')


    
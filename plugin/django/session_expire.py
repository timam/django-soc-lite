from datetime import datetime
from django.http import HttpResponseRedirect

class SessionExpiredMiddleware:
    def process_request(request):
        last_activity = request.session['last_activity']
        now = datetime.now()

        if (now - last_activity).minutes > 10:
            return HttpResponseRedirect("LOGIN_PAGE_URL")

        if not request.is_ajax():
            request.session['last_activity'] = now
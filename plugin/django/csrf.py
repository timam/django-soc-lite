from __future__ import absolute_import, division, print_function
from django.conf import settings
from django.http import HttpResponseForbidden
from plugin import client_id, port, server
from plugin.info import send_client_info
from django.core.urlresolvers import get_callable
from django.utils.cache import patch_vary_headers
from django.utils.hashcompat import md5_constructor
from django.utils.safestring import mark_safe

import requests
import md5
import re
import itertools
import random

from datetime import datetime

_POST_FORM_RE = \
    re.compile(r'(<form\W[^>]*\bmethod\s*=\s*(\'|"|)POST(\'|"|)\b[^>]*>)', re.IGNORECASE)
_HTML_TYPES = ('text/html', 'application/xhtml+xml')

if hasattr(random, 'SystemRandom'):
    randrange = random.SystemRandom().randrange
else:
    randrange = random.randrange
_MAX_CSRF_KEY = 18446744073709551616L    
REASON_NO_REFERER = "Referer checking failed - no Referer."
REASON_BAD_REFERER = "Referer checking failed - %s does not match %s."
REASON_NO_COOKIE = "No CSRF or session cookie."
REASON_NO_CSRF_COOKIE = "CSRF cookie not set."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."
def _get_failure_view():
    return get_callable(settings.CSRF_FAILURE_VIEW)
def _get_new_csrf_key():
    return md5_constructor("%s%s"
                % (randrange(0, _MAX_CSRF_KEY), settings.SECRET_KEY)).hexdigest()
def _make_legacy_session_token(session_id):
    return md5_constructor(settings.SECRET_KEY + session_id).hexdigest()
def get_token(request):
    request.META["CSRF_COOKIE_USED"] = True
    return request.META.get("CSRF_COOKIE", None)
def _sanitize_token(token):
    token = re.sub('[^a-zA-Z0-9]', '', str(token.decode('ascii', 'ignore')))
    if token == "":
        return _get_new_csrf_key()
    else:
        return token
class CsrfViewMiddleware(object):
    def _accept(self, request):
        request.csrf_processing_done = True
        return None
    def _reject(self, request, reason):
        return _get_failure_view()(request, reason=reason)
    def process_view(self, request, callback, callback_args, callback_kwargs):
        if getattr(request, 'csrf_processing_done', False):
            return None
        try:
            request.META["CSRF_COOKIE"] = _sanitize_token(request.COOKIES[settings.CSRF_COOKIE_NAME])
            cookie_is_new = False
        except KeyError:
            request.META["CSRF_COOKIE"] = _get_new_csrf_key()
            cookie_is_new = True
        if getattr(callback, 'csrf_exempt', False):
            return None
        if request.method == 'POST':
            if getattr(request, '_dont_enforce_csrf_checks', False):
                return self._accept(request)
            if request.is_secure():
                referer = request.META.get('HTTP_REFERER')
                if referer is None:
                    return self._reject(request, REASON_NO_REFERER)
                good_referer = 'https://%s/' % request.get_host()
                if not referer.startswith(good_referer):
                    return self._reject(request, REASON_BAD_REFERER %
                                        (referer, good_referer))
            if cookie_is_new:
                try:
                    session_id = request.COOKIES[settings.SESSION_COOKIE_NAME]
                    csrf_token = _make_legacy_session_token(session_id)
                except KeyError:
                    return self._reject(request, REASON_NO_COOKIE)
            else:
                csrf_token = request.META["CSRF_COOKIE"]
         
            request_csrf_token = request.POST.get('csrfmiddlewaretoken', "")
            if request_csrf_token == "":
                request_csrf_token = request.META.get('HTTP_X_CSRFTOKEN', '')
            if request_csrf_token != csrf_token:
                if cookie_is_new:
                    return self._reject(request, REASON_NO_CSRF_COOKIE)
                else:
                    return self._reject(request, REASON_BAD_TOKEN)
        return self._accept(request)
    def process_response(self, request, response):
        if getattr(response, 'csrf_processing_done', False):
            return response
        if request.META.get("CSRF_COOKIE") is None:
            return response
        if not request.META.get("CSRF_COOKIE_USED", False):
            return response
        response.set_cookie(settings.CSRF_COOKIE_NAME,
                request.META["CSRF_COOKIE"], max_age = 60 * 60 * 24 * 7 * 52,
                domain=settings.CSRF_COOKIE_DOMAIN)
        patch_vary_headers(response, ('Cookie',))
        response.csrf_processing_done = True
        return response
class CsrfResponseMiddleware(object):
    def __init__(self):
        import warnings
        warnings.warn(
            "CsrfResponseMiddleware and CsrfMiddleware are deprecated; use CsrfViewMiddleware and the template tag instead (see CSRF documentation).",
            PendingDeprecationWarning
        )
    def process_response(self, request, response):
        if getattr(response, 'csrf_exempt', False):
            return response
        if response['Content-Type'].split(';')[0] in _HTML_TYPES:
            csrf_token = get_token(request)
            if csrf_token is None:
                return response
            # ensure we don't add the 'id' attribute twice (HTML validity)
            idattributes = itertools.chain(("id='csrfmiddlewaretoken'",),
                                           itertools.repeat(''))
            def add_csrf_field(match):
                """Returns the matched <form> tag plus the added <input> element"""
                return mark_safe(match.group() + "<div style='display:none;'>" + \
                "<input type='hidden' " + idattributes.next() + \
                " name='csrfmiddlewaretoken' value='" + csrf_token + \
                "' /></div>")
           
            response.content, n = _POST_FORM_RE.subn(add_csrf_field, response.content)
            if n > 0:
                patch_vary_headers(response, ('Cookie',))
                del response['ETag']
        return response
class ThreatCsrfMiddleware(object):
    def __init__(self):
        self.response_middleware = CsrfResponseMiddleware()
        self.view_middleware = CsrfViewMiddleware()
    def process_response(self, request, resp):
        resp2 = self.response_middleware.process_response(request, resp)
        return self.view_middleware.process_response(request, resp2)
    def process_view(self, request, callback, callback_args, callback_kwargs):
        return self.view_middleware.process_view(request, callback, callback_args,
                                                 callback_kwargs)


        

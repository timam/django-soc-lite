from django.conf import settings
class RatelimitMiddleware(object):
    def process_exception(self, request):
        if not isinstance(Ratelimited):
            return
        module_name, _, view_name = settings.RATELIMIT_VIEW.rpartition('.')
        module = import_module(module_name)
        view = getattr(module, view_name)
        return view(request)
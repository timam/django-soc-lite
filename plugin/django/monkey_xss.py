from __future__ import absolute_import, division, print_function


saved = {}

_NONE = object()


def patch_item(module, attr, newitem):
    olditem = getattr(module, attr, _NONE)
    if olditem is not _NONE:
        saved.setdefault(module.__name__, {}).setdefault(attr, olditem)
    setattr(module, attr, newitem)

def patch_all():
    xss_module = __import__("xss")
    from plugin.django.xss import requests
    patch_item(xss_module, "process_request", request)
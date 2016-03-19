from __future__ import absolute_import


saved = {}

_NONE = object()


def patch_item(module, attr, newitem):
    olditem = getattr(module, attr, _NONE)
    if olditem is not _NONE:
        saved.setdefault(module.__name__, {}).setdefault(attr, olditem)
    setattr(module, attr, newitem)


def patch_all():
    os_module = __import__("os")
    from plugin.os import system
    patch_item(os_module, "system", system)

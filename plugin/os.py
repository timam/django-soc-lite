import os
import re

from shellescape import quote


__implements__ = ["system"]
_find_potential_attacks = re.compile(r"[;$`|&><-]").search

_system = os.system

def system(command):
    if _find_potential_attacks(command) is not None:
        print("Attack found!")

    return _system(quote(command))

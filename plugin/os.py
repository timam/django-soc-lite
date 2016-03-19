from datetime import datetime
import os
import re
import traceback

from shellescape import quote
from structlog import get_logger


__implements__ = ["system"]
_find_potential_attacks = re.compile(r"[;$`|&><-]").search

_system = os.system

_logger = get_logger()

def system(command):
    if _find_potential_attacks(command) is not None:
        _logger.info(
            "injection attempt",
            stacktrace=traceback.format_stack(),
            timestamp=datetime.utcnow(),
            data=command
        )

    return _system(quote(command))

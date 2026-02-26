import sys
from zappa.utilities import is_supported_version


if not is_supported_version():
    raise RuntimeError(f"Python {sys.version_info[0]}.{sys.version_info[1]} is not supported!")

__version__ = "0.54.0"

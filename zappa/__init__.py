import sys

MINIMUM_SUPPORTED_MINOR = 8
MAXIMUM_SUPPORTED_MINOR = 13

if sys.version_info[0] != 3 or not (MINIMUM_SUPPORTED_MINOR <= sys.version_info[1] <= MAXIMUM_SUPPORTED_MINOR):
    supported_range = f"3.{MINIMUM_SUPPORTED_MINOR}-3.{MAXIMUM_SUPPORTED_MINOR}"
    current = f"{sys.version_info[0]}.{sys.version_info[1]}"
    raise RuntimeError(
        f"This version of Python ({current}) is not supported!\n"
        f"Zappa (and AWS Lambda) support Python {supported_range}."
    )

__version__ = "0.54.0"

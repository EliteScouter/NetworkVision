import os

try:  # written by the native package builds (packaging/), never committed
    from ._build_version import VERSION as _BUILD_VERSION
except ImportError:
    _BUILD_VERSION = ""

# CI stamps the release tag into the image (NV_VERSION); this is the dev fallback.
__version__ = os.environ.get("NV_VERSION") or _BUILD_VERSION or "0.5.5-dev"

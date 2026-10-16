import os

# CI stamps the release tag into the image (NV_VERSION); this is the dev fallback.
__version__ = os.environ.get("NV_VERSION") or "0.4.8-dev"

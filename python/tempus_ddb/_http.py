"""Shared HTTP opener for the packaged executors: redirects are refused.

``urllib.request.urlopen`` follows 3xx responses and forwards the ``Authorization``
header to the new host. The executors hold downstream credentials, so every transport
opens requests through :func:`open_request`, whose opener raises
:class:`RedirectRefused` instead of following a redirect. The error carries only the
status code and the target *host* (never the full ``Location``, which may contain
tokens in its path or query).
"""

import re
from urllib import parse, request

_HOST_SAFE = re.compile(r"[^A-Za-z0-9.\-:\[\]]")


class RedirectRefused(Exception):
    """A 3xx response was received and deliberately not followed."""

    def __init__(self, status_code: int, target_host: str):
        self.status_code = status_code
        self.target_host = target_host
        super().__init__(
            f"HTTP {status_code} redirect refused (not followed; credentials were "
            f"not forwarded); redirect target host: {target_host or 'unknown'}"
        )


def _safe_host(base_url: str, location: str) -> str:
    try:
        host = parse.urlsplit(parse.urljoin(base_url, location)).hostname or ""
    except ValueError:
        return ""
    return _HOST_SAFE.sub("?", host)[:255]


class _RejectRedirects(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectRefused(code, _safe_host(req.full_url, newurl))


_OPENER = request.build_opener(_RejectRedirects)


def open_request(req: request.Request, timeout: float):
    """Open ``req`` like ``urlopen`` but never follow a redirect."""
    return _OPENER.open(req, timeout=timeout)

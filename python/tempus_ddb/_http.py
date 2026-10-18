"""Shared HTTP opener for the packaged executors: redirects are refused.

``urllib.request.urlopen`` follows 3xx responses and forwards the ``Authorization``
header to the new host. The executors hold downstream credentials, so every transport
opens requests through :func:`open_request`, whose opener raises
:class:`RedirectRefused` instead of following a redirect. The error carries only the
status code and the target *host* (never the full ``Location``, which may contain
tokens in its path or query).
"""

import http.client
import ipaddress
import re
import socket
from typing import List, Optional, Union
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


# --------------------------------------------------------------- destination filter
#
# The HTTP executor sends a caller-chosen URL, so it must not be usable to reach the
# machine's own services, the private network or the cloud metadata endpoint. The check
# is made on addresses, never on the spelling of the host: `127.1`, `2130706433`,
# `0x7f000001` or `[::ffff:127.0.0.1]` are all the same loopback address.


class DestinationRefused(Exception):
    """The host is, or resolves to, an address the executor never connects to."""


_IP = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Not covered (or not reliably) by `is_global`: CGNAT, multicast and cloud metadata
# addresses that live in otherwise public space (Azure WireServer) or in old ranges.
_EXTRA_BLOCKED_V4 = [
    ipaddress.ip_network(net)
    for net in (
        "100.64.0.0/10",  # carrier-grade NAT (includes Alibaba metadata 100.100.100.200)
        "224.0.0.0/4",  # multicast
        "168.63.129.16/32",  # Azure WireServer / metadata helper
        "169.254.169.254/32",  # AWS, GCP, Azure, OpenStack... metadata
        "192.0.0.192/32",  # Oracle Cloud metadata (legacy)
    )
]
_BLOCKED_NAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}


def parse_host_ip(host: str) -> Optional[_IP]:
    """The IP address a host *string* stands for, or None if it is a name.

    Besides canonical IPv4/IPv6, this reads what the OS resolver reads (``inet_aton``):
    ``127.1``, ``2130706433``, ``0x7f000001``, ``0177.0.0.1``, ``10.1``, ``0``.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def blocked_reason(ip: _IP) -> Optional[str]:
    """Why the executor refuses to connect to ``ip`` (None when it may)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return blocked_reason(ip.ipv4_mapped)
        if ip in _NAT64:  # DNS64 answers on IPv6-only networks: judge the IPv4 inside
            return blocked_reason(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        # Only global unicast is allowed: this drops ::1, ::, ::/96 (IPv4-compatible),
        # fe80::/10, fc00::/7 (ULA, AWS fd00:ec2::254), ff00::/8 and the rest.
        if ip not in _GLOBAL_UNICAST_V6 or not ip.is_global:
            return "not a global unicast IPv6 address"
        if ip.sixtofour is not None or ip.teredo is not None:
            return "6to4/Teredo tunnel address"
        return None
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        return "loopback, private, link-local, reserved or unspecified IPv4 address"
    for net in _EXTRA_BLOCKED_V4:
        if ip in net:
            return "CGNAT, multicast or cloud metadata address"
    return None


def check_host_literal(host: str) -> None:
    """Refuse names and IP spellings that are blocked without any DNS lookup."""
    name = host.lower().rstrip(".")
    if name in _BLOCKED_NAMES or name.endswith(".localhost"):
        raise DestinationRefused(f"host '{host}' is a local name")
    ip = parse_host_ip(name)
    if ip is not None:
        reason = blocked_reason(ip)
        if reason:
            raise DestinationRefused(f"host '{host}' is {ip}: {reason}")


def resolve_public(host: str, port: int) -> List[str]:
    """Resolve ``host`` and return its addresses, all checked; refuse if any is blocked.

    One bad answer refuses the whole name: a name that maps to a private address for any
    client is not treated as public just because another answer is.
    """
    check_host_literal(host)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise DestinationRefused(f"cannot resolve host '{host}': {exc}") from exc
    addresses: List[str] = []
    for info in infos:
        text = info[4][0].split("%", 1)[0]
        ip = parse_host_ip(text)
        if ip is None:
            raise DestinationRefused(f"host '{host}' resolved to a non-IP answer")
        reason = blocked_reason(ip)
        if reason:
            raise DestinationRefused(f"host '{host}' resolves to {ip}: {reason}")
        if text not in addresses:
            addresses.append(text)
    if not addresses:
        raise DestinationRefused(f"host '{host}' did not resolve")
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to the address it has just validated.

    The name is resolved once, every answer is checked, and the socket goes to one of
    those exact IPs, so the name cannot resolve to something else between the check and
    the connect (DNS rebinding). TLS still verifies the certificate against the host
    *name* (``server_hostname``). Through an HTTP(S) proxy (environment variables) the
    proxy resolves the target itself: the name is checked here first, but that check
    cannot be pinned.
    """

    def connect(self):
        if self._tunnel_host:
            resolve_public(self._tunnel_host, self._tunnel_port or 443)
            return super().connect()
        last_error: Optional[OSError] = None
        for address in resolve_public(self.host, self.port):
            try:
                sock = socket.create_connection(
                    (address, self.port), self.timeout, self.source_address
                )
            except OSError as exc:
                last_error = exc
                continue
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            return
        raise last_error or OSError(f"cannot connect to {self.host}")


class _PinnedHTTPSHandler(request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


_PINNED_OPENER = request.build_opener(_RejectRedirects, _PinnedHTTPSHandler)


def open_request(req: request.Request, timeout: float, pinned: bool = False):
    """Open ``req`` like ``urlopen`` but never follow a redirect.

    ``pinned=True`` also refuses private/loopback/metadata destinations and connects to
    the validated address (see :class:`_PinnedHTTPSConnection`); the HTTP executor uses it.
    """
    opener = _PINNED_OPENER if pinned else _OPENER
    return opener.open(req, timeout=timeout)

"""
tools/url_validator.py — Deterministic URL safety checker.

Replaces the LLM-based URL Validator agent with a three-stage pipeline:

  1. Filter  — private RFC 1918 / APIPA / loopback IPs and well-known
               public DNS server addresses are dropped entirely.
  2. Resolve — domain names are resolved to IPv4 addresses using
               Google DNS over HTTPS (dns.google/resolve).
  3. DNSBL   — each public IP is checked against the Spamhaus ZEN
               combined block list via a direct query to Spamhaus's own
               authoritative nameservers (bypassing Google/Cloudflare,
               which block DNSBL traffic by policy).

Returns URLVerdict-compatible dicts consumed directly by the runner,
with no LLM involvement.
"""

import ipaddress
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

import dns.exception
import dns.resolver


_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Private / reserved network ranges
# ---------------------------------------------------------------------------

# URLs whose host resolves to any of these are filtered out completely.
# They represent internal infrastructure, not external threats.
_PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 class A
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 class B
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 class C
    ipaddress.ip_network("169.254.0.0/16"),    # APIPA / link-local
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space
]

# Public DNS resolver IPs that appear legitimately in image configs.
# Checking them against Spamhaus would produce false positives because
# they are infrastructure servers, not origin servers.
_PUBLIC_DNS_SERVER_IPS: frozenset[str] = frozenset({
    "1.1.1.1", "1.0.0.1",      # Cloudflare
    "8.8.8.8", "8.8.4.4",      # Google
})

# Spamhaus returns these codes for operational reasons, not because the
# queried IP is actually listed. Treat them as inconclusive to avoid
# false positives when the free-tier query limit is hit.
_SPAMHAUS_OPERATIONAL_RETURN_CODES: frozenset[str] = frozenset({
    "127.255.255.252",  # Typo in the DNS query
    "127.255.255.254",  # Query limit reached (free tier exceeded)
    "127.255.255.255",  # Querying IP is itself blocked by Spamhaus
})

# Spamhaus GNS (Global Name Server) hostnames.
# These are resolved at module load via the system resolver — normal
# hostname lookups work through any resolver. Only the DNSBL queries
# themselves are blocked by Google/Cloudflare, so we resolve the GNS
# IPs first and then query them directly for all DNSBL lookups.
_SPAMHAUS_GNS_HOSTNAMES: tuple[str, ...] = (
    "a.gns.spamhaus.org",
    "b.gns.spamhaus.org",
    "c.gns.spamhaus.org",
    "d.gns.spamhaus.org",
    "e.gns.spamhaus.org",
)

_GOOGLE_DOH_BASE_URL = "https://dns.google/resolve"
_SPAMHAUS_ZEN_SUFFIX = ".zen.spamhaus.org"
_HTTP_TIMEOUT_SECONDS = 5
_DNS_TIMEOUT_SECONDS = 5


# ---------------------------------------------------------------------------
# Spamhaus nameserver bootstrap
# ---------------------------------------------------------------------------

def _resolve_spamhaus_nameserver_ips() -> list[str]:
    """
    Resolve the IPv4 addresses of Spamhaus GNS servers at module load.

    Uses the system resolver, which works for regular hostname lookups
    even when DNSBL traffic is blocked. Falls back to an empty list if
    all resolutions fail; _check_ip_against_spamhaus_zen will handle
    that case gracefully.
    """
    nameserver_ips: list[str] = []
    for hostname in _SPAMHAUS_GNS_HOSTNAMES:
        try:
            answers = dns.resolver.resolve(hostname, "A")
            nameserver_ips.extend(str(record) for record in answers)
        except dns.exception.DNSException as exc:
            _log.debug("Could not resolve Spamhaus GNS %s: %s", hostname, exc)
    return nameserver_ips


# Resolved once at import time and reused for every DNSBL query.
_SPAMHAUS_NAMESERVER_IPS: list[str] = _resolve_spamhaus_nameserver_ips()


# ---------------------------------------------------------------------------
# IP classification helpers
# ---------------------------------------------------------------------------

def _is_private_or_reserved(ip_string: str) -> bool:
    """
    Return True if the IPv4 address falls within any private or
    reserved network range defined in _PRIVATE_NETWORKS.
    """
    try:
        addr = ipaddress.ip_address(ip_string)
        return any(addr in network for network in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _is_known_dns_server(ip_string: str) -> bool:
    """
    Return True if the IP belongs to a well-known public DNS resolver.

    These addresses appear legitimately in Docker image configs and
    should not be treated as suspicious endpoints.
    """
    return ip_string in _PUBLIC_DNS_SERVER_IPS


# ---------------------------------------------------------------------------
# Google DNS over HTTPS resolution
# ---------------------------------------------------------------------------

def _resolve_domain_via_google_doh(
    domain: str,
) -> tuple[list[str], str | None]:
    """
    Resolve a domain name to IPv4 addresses using Google DNS over HTTPS.

    Uses dns.google/resolve with type=A so the resolution is independent
    of the host machine's system resolver, which may be misconfigured
    or have split-horizon DNS that hides public addresses.

    Returns (ip_list, error_message). ip_list is empty and error_message
    is set when resolution fails.
    """
    query_params = urllib.parse.urlencode({"name": domain, "type": "A"})
    request_url = f"{_GOOGLE_DOH_BASE_URL}?{query_params}"
    try:
        request = urllib.request.Request(
            request_url,
            headers={"Accept": "application/dns-json"},
        )
        with urllib.request.urlopen(
            request, timeout=_HTTP_TIMEOUT_SECONDS
        ) as response:
            payload = json.loads(response.read())
        # Type 1 = DNS A record (IPv4)
        resolved_ips = [
            record["data"]
            for record in payload.get("Answer", [])
            if record.get("type") == 1
        ]
        return resolved_ips, None
    except urllib.error.URLError as exc:
        return [], str(exc)
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


# ---------------------------------------------------------------------------
# Spamhaus ZEN DNSBL check
# ---------------------------------------------------------------------------

def _build_spamhaus_resolver() -> dns.resolver.Resolver:
    """
    Build a dnspython Resolver configured to query Spamhaus GNS servers.

    Bypasses the system resolver (which may be Google/Cloudflare DNS —
    both block Spamhaus DNSBL traffic by policy) by pointing directly at
    the Spamhaus authoritative nameservers resolved at module load.
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = _SPAMHAUS_NAMESERVER_IPS
    resolver.timeout = _DNS_TIMEOUT_SECONDS
    # lifetime caps the total time across all retries
    resolver.lifetime = _DNS_TIMEOUT_SECONDS * 2
    return resolver


def _check_ip_against_spamhaus_zen(
    ip_string: str,
) -> tuple[bool, str]:
    """
    Query the Spamhaus ZEN combined block list for the given IPv4 address.

    Reverses the four octets and appends .zen.spamhaus.org, then queries
    Spamhaus's own nameservers directly so the lookup is not intercepted
    by public resolvers. Any 127.0.0.x response means the IP is listed;
    127.255.255.x operational codes are treated as inconclusive.

    Returns (is_listed, reason_string). is_listed is False on NXDOMAIN
    (clean IP) or when no actionable return code is present.
    """
    if not _SPAMHAUS_NAMESERVER_IPS:
        _log.warning(
            "No Spamhaus GNS IPs available; skipping ZEN check for %s",
            ip_string,
        )
        return False, ""

    reversed_octets = ".".join(reversed(ip_string.split(".")))
    lookup_hostname = f"{reversed_octets}{_SPAMHAUS_ZEN_SUFFIX}"
    resolver = _build_spamhaus_resolver()

    try:
        answers = resolver.resolve(lookup_hostname, "A")
        return_codes = {str(record) for record in answers}

        # Strip operational codes — only flag real block-list hits.
        actionable_codes = return_codes - _SPAMHAUS_OPERATIONAL_RETURN_CODES
        if not actionable_codes:
            return False, ""

        return (
            True,
            f"Spamhaus ZEN listed: {', '.join(sorted(actionable_codes))}",
        )
    except dns.resolver.NXDOMAIN:
        # NXDOMAIN means the IP is not listed in any ZEN sub-list.
        return False, ""
    except dns.exception.DNSException as exc:
        _log.debug("Spamhaus ZEN lookup failed for %s: %s", ip_string, exc)
        return False, ""


# ---------------------------------------------------------------------------
# Per-finding verdict logic
# ---------------------------------------------------------------------------

def _extract_host(url_string: str) -> str | None:
    """
    Extract the hostname or IP from a URL string or bare IP.

    Returns None when the host cannot be determined.
    """
    if url_string.startswith("http"):
        try:
            return urlparse(url_string).hostname or None
        except ValueError:
            return None
    # Bare IP or IP:port without a scheme
    return url_string.split(":")[0].split("/")[0] or None


def _verdict_for_public_ip(
    ip_string: str,
    original_url: str,
    resolved_from: str | None = None,
) -> dict:
    """
    Run a Spamhaus ZEN check on a single public IPv4 address and return
    a URLVerdict dict for the original URL.

    resolved_from is the domain name that produced ip_string via DNS;
    it is appended to the reason when present for easier debugging.
    """
    is_listed, reason = _check_ip_against_spamhaus_zen(ip_string)
    if is_listed:
        suffix = (
            f" (resolved from {resolved_from})" if resolved_from else ""
        )
        return {
            "url": original_url,
            "verdict": "Not Safe",
            "reason": f"{reason}{suffix}",
        }
    suffix = f" → {ip_string}" if resolved_from else ""
    return {
        "url": original_url,
        "verdict": "Safe",
        "reason": f"IP not listed in Spamhaus ZEN{suffix}",
    }


def _evaluate_url_finding(finding: dict) -> dict | None:
    """
    Evaluate one URL finding and return a URLVerdict dict, or None.

    None is returned when the finding should be filtered out entirely:
    private/reserved IPs and known public DNS server addresses are
    silently dropped because they are not external threats.

    For domain names the host is first resolved via Google DoH; each
    resulting public IP is then checked against Spamhaus ZEN. The URL
    is marked Not Safe if any resolved IP is listed.
    """
    url_string = finding.get("url", "")
    host = _extract_host(url_string)
    if not host:
        return None

    # Determine whether the host is already a bare IP address.
    try:
        ipaddress.ip_address(host)
        host_is_bare_ip = True
    except ValueError:
        host_is_bare_ip = False

    if host_is_bare_ip:
        if _is_known_dns_server(host) or _is_private_or_reserved(host):
            return None  # Filter out — not an external threat
        return _verdict_for_public_ip(host, url_string)

    # Domain name — resolve via Google DoH first.
    resolved_ips, resolution_error = _resolve_domain_via_google_doh(host)
    if resolution_error and not resolved_ips:
        return {
            "url": url_string,
            "verdict": "Not Safe",
            "reason": f"DNS resolution failed: {resolution_error}",
        }

    public_ips = [
        ip for ip in resolved_ips
        if not _is_private_or_reserved(ip)
        and not _is_known_dns_server(ip)
    ]
    if not public_ips:
        # Domain resolves entirely to private/reserved space — filter out.
        return None

    # Flag the URL on the first listed IP found.
    for ip in public_ips:
        verdict = _verdict_for_public_ip(ip, url_string, resolved_from=host)
        if verdict["verdict"] == "Not Safe":
            return verdict

    # All resolved IPs passed the ZEN check.
    resolved_summary = ", ".join(public_ips)
    return {
        "url": url_string,
        "verdict": "Safe",
        "reason": f"All resolved IPs clean ({resolved_summary})",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_urls(url_findings: list[dict]) -> list[dict]:
    """
    Validate a list of URL findings and return URLVerdict dicts.

    Applies a three-stage pipeline to each finding:
      1. Filters private-range IPs and public DNS server addresses.
      2. Resolves domain names to IPs via Google DNS over HTTPS.
      3. Checks each public IP against Spamhaus ZEN via direct query
         to Spamhaus's own authoritative nameservers.

    Findings that resolve entirely to private/reserved space are
    excluded from the output (not included even as Safe verdicts).

    Args:
        url_findings: List of dicts from url_extractor.extract_urls,
                      each containing at least a 'url' key.

    Returns:
        List of URLVerdict-compatible dicts (url, verdict, reason).
        Filtered entries are omitted entirely.
    """
    verdicts = []
    for finding in url_findings:
        verdict = _evaluate_url_finding(finding)
        if verdict is not None:
            verdicts.append(verdict)
    return verdicts

"""
ip_intel.py
IP Intelligence module — resolves IP addresses to geographic and
organizational metadata.

Resolution order (fastest to slowest):
  1. This Device       — socket-detected local IPs
  2. Private ranges    — RFC1918 / loopback / link-local
  3. Known ranges      — hardcoded well-known service prefixes
  4. Extended ranges   — broader ASN/org prefix table
  5. ip-api.com        — free geolocation API (no key, 45 req/min)
  6. Reverse DNS       — hostname lookup as last resort
  7. Graceful fallback — partial info always returned, never a blank

All results cached in memory. Lookups for unknown IPs are non-blocking.
"""

import socket
import logging
import threading
import time
import urllib.request
import urllib.error
import json
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Cache                                                               #
# ------------------------------------------------------------------ #
_cache: Dict[str, dict] = {}
_cache_lock = threading.Lock()

# Rate limiting for ip-api.com (45 req/min free tier)
_last_request_ts = 0.0
_request_lock    = threading.Lock()
MIN_REQUEST_GAP  = 60 / 44   # ~1.36s between requests

# ------------------------------------------------------------------ #
# Well-known service ranges (checked before any API call)            #
# ------------------------------------------------------------------ #
KNOWN_RANGES = [
    # Apple
    ('17.',          'Apple Inc.',            'Apple Services'),
    # Telegram
    ('91.108.',      'Telegram',              'Telegram Messaging'),
    ('149.154.',     'Telegram',              'Telegram Messaging'),
    ('95.161.',      'Telegram',              'Telegram Messaging'),
    # Google
    ('8.8.8.',       'Google LLC',            'Google Public DNS'),
    ('8.8.4.',       'Google LLC',            'Google Public DNS'),
    ('142.250.',     'Google LLC',            'Google Services'),
    ('172.217.',     'Google LLC',            'Google Services'),
    ('216.58.',      'Google LLC',            'Google Services'),
    ('64.233.',      'Google LLC',            'Google Services'),
    ('74.125.',      'Google LLC',            'Google Services'),
    ('34.64.',       'Google Cloud',          'Google Cloud Platform'),
    ('34.65.',       'Google Cloud',          'Google Cloud Platform'),
    ('35.186.',      'Google Cloud',          'Google Cloud Platform'),
    # Cloudflare
    ('1.1.1.',       'Cloudflare Inc.',       'Cloudflare DNS'),
    ('1.0.0.',       'Cloudflare Inc.',       'Cloudflare DNS'),
    ('104.16.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('104.17.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('104.18.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('104.19.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('104.20.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('104.21.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('172.64.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('172.65.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('172.66.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('172.67.',      'Cloudflare Inc.',       'Cloudflare CDN'),
    ('198.41.128.',  'Cloudflare Inc.',       'Cloudflare CDN'),
    # Meta / Facebook
    ('31.13.',       'Meta Platforms',        'Facebook / Instagram'),
    ('157.240.',     'Meta Platforms',        'Facebook / Instagram'),
    ('179.60.',      'Meta Platforms',        'Facebook / WhatsApp'),
    ('185.60.',      'Meta Platforms',        'Facebook / WhatsApp'),
    # Amazon AWS
    ('13.32.',       'Amazon AWS',            'AWS CloudFront'),
    ('13.33.',       'Amazon AWS',            'AWS CloudFront'),
    ('13.34.',       'Amazon AWS',            'AWS CloudFront'),
    ('13.35.',       'Amazon AWS',            'AWS CloudFront'),
    ('13.224.',      'Amazon AWS',            'AWS CloudFront'),
    ('13.225.',      'Amazon AWS',            'AWS CloudFront'),
    ('13.226.',      'Amazon AWS',            'AWS CloudFront'),
    ('13.227.',      'Amazon AWS',            'AWS CloudFront'),
    ('52.',          'Amazon AWS',            'AWS EC2'),
    ('54.',          'Amazon AWS',            'AWS EC2'),
    ('18.',          'Amazon AWS',            'AWS Services'),
    ('3.',           'Amazon AWS',            'AWS Services'),
    # Microsoft Azure
    ('13.64.',       'Microsoft Azure',       'Azure Services'),
    ('13.65.',       'Microsoft Azure',       'Azure Services'),
    ('13.66.',       'Microsoft Azure',       'Azure Services'),
    ('13.67.',       'Microsoft Azure',       'Azure Services'),
    ('20.',          'Microsoft Azure',       'Azure Services'),
    ('40.',          'Microsoft Azure',       'Azure / Office 365'),
    ('52.224.',      'Microsoft Azure',       'Azure Services'),
    ('104.40.',      'Microsoft Azure',       'Azure Services'),
    ('104.41.',      'Microsoft Azure',       'Azure Services'),
    ('104.42.',      'Microsoft Azure',       'Azure Services'),
    # GitHub
    ('185.199.',     'GitHub Inc.',           'GitHub Services'),
    ('140.82.',      'GitHub Inc.',           'GitHub Services'),
    ('192.30.',      'GitHub Inc.',           'GitHub Services'),
    # Fastly CDN
    ('151.101.',     'Fastly Inc.',           'Fastly CDN'),
    ('199.232.',     'Fastly Inc.',           'Fastly CDN'),
    # Akamai
    ('23.32.',       'Akamai Technologies',   'Akamai CDN'),
    ('23.33.',       'Akamai Technologies',   'Akamai CDN'),
    ('23.34.',       'Akamai Technologies',   'Akamai CDN'),
    ('23.35.',       'Akamai Technologies',   'Akamai CDN'),
    ('104.64.',      'Akamai Technologies',   'Akamai CDN'),
    ('104.65.',      'Akamai Technologies',   'Akamai CDN'),
    # Akamai / Linode
    ('172.233.',     'Akamai / Linode',       'Linode Cloud'),
    # DigitalOcean
    ('67.205.',      'DigitalOcean',          'DigitalOcean Cloud'),
    ('104.131.',     'DigitalOcean',          'DigitalOcean Cloud'),
    ('138.197.',     'DigitalOcean',          'DigitalOcean Cloud'),
    ('159.203.',     'DigitalOcean',          'DigitalOcean Cloud'),
    ('167.172.',     'DigitalOcean',          'DigitalOcean Cloud'),
    ('178.62.',      'DigitalOcean',          'DigitalOcean Cloud'),
    # Spotify
    ('35.186.',      'Spotify AB',            'Spotify Streaming'),
    ('104.199.',     'Spotify AB',            'Spotify Streaming'),
    # Netflix
    ('23.246.',      'Netflix Inc.',          'Netflix CDN'),
    ('37.77.',       'Netflix Inc.',          'Netflix CDN'),
    ('45.57.',       'Netflix Inc.',          'Netflix CDN'),
    ('198.38.',      'Netflix Inc.',          'Netflix CDN'),
    ('208.75.',      'Netflix Inc.',          'Netflix CDN'),
    # Apple iCloud / CDN
    ('17.248.',      'Apple Inc.',            'Apple iCloud CDN'),
    ('17.57.',       'Apple Inc.',            'Apple CDN'),
    ('17.32.',       'Apple Inc.',            'Apple Push Notifications'),
    # Zoom
    ('99.79.',       'Zoom Video',            'Zoom Meetings'),
    ('170.114.',     'Zoom Video',            'Zoom Meetings'),
    ('173.231.',     'Zoom Video',            'Zoom Meetings'),
    # Slack
    ('54.172.',      'Slack Technologies',    'Slack'),
    ('34.232.',      'Slack Technologies',    'Slack'),
    # WhatsApp (Meta)
    ('31.13.',       'Meta / WhatsApp',       'WhatsApp'),
    # Twitch
    ('192.16.64.',   'Twitch Interactive',    'Twitch Streaming'),
    ('192.16.70.',   'Twitch Interactive',    'Twitch Streaming'),
    # YouTube (Google)
    ('216.239.',     'Google / YouTube',      'YouTube CDN'),
    # OpenDNS
    ('208.67.',      'Cisco OpenDNS',         'OpenDNS'),
    # Quad9
    ('9.9.9.',       'Quad9',                 'Quad9 DNS'),
]

PRIVATE_RANGES = [
    ('127.',         'Loopback',              'Localhost'),
    ('10.',          'Private Network',        'RFC1918 LAN'),
    ('192.168.',     'Private Network',        'RFC1918 LAN'),
    ('172.16.',      'Private Network',        'RFC1918 LAN'),
    ('172.17.',      'Private Network',        'RFC1918 LAN'),
    ('172.18.',      'Private Network',        'RFC1918 LAN'),
    ('172.19.',      'Private Network',        'RFC1918 LAN'),
    ('172.20.',      'Private Network',        'RFC1918 LAN'),
    ('172.21.',      'Private Network',        'RFC1918 LAN'),
    ('172.22.',      'Private Network',        'RFC1918 LAN'),
    ('172.23.',      'Private Network',        'RFC1918 LAN'),
    ('172.24.',      'Private Network',        'RFC1918 LAN'),
    ('172.25.',      'Private Network',        'RFC1918 LAN'),
    ('172.26.',      'Private Network',        'RFC1918 LAN'),
    ('172.27.',      'Private Network',        'RFC1918 LAN'),
    ('172.28.',      'Private Network',        'RFC1918 LAN'),
    ('172.29.',      'Private Network',        'RFC1918 LAN'),
    ('172.30.',      'Private Network',        'RFC1918 LAN'),
    ('172.31.',      'Private Network',        'RFC1918 LAN'),
    ('169.254.',     'Link-Local',             'APIPA / Link-Local'),
    ('100.64.',      'Shared Address Space',   'CGN / ISP Internal'),
    ('198.18.',      'Benchmark Testing',      'RFC2544 Test Range'),
    ('198.19.',      'Benchmark Testing',      'RFC2544 Test Range'),
    ('192.0.2.',     'Documentation',          'TEST-NET-1'),
    ('198.51.100.',  'Documentation',          'TEST-NET-2'),
    ('203.0.113.',   'Documentation',          'TEST-NET-3'),
    ('240.',         'Reserved',               'Future Use / Multicast'),
    ('224.',         'Multicast',              'IP Multicast'),
]


# ------------------------------------------------------------------ #
# Local IP detection                                                  #
# ------------------------------------------------------------------ #

def _get_local_ips() -> set:
    ips = {'127.0.0.1', '::1', 'localhost'}
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            if ':' not in ip:
                ips.add(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


LOCAL_IPS = _get_local_ips()
logger.info("Local IPs detected: %s", LOCAL_IPS)


# ------------------------------------------------------------------ #
# Range matching helpers                                              #
# ------------------------------------------------------------------ #

def _match_ranges(ip: str, ranges: list) -> Optional[dict]:
    """Check IP against an ordered list of (prefix, org, service) tuples."""
    for prefix, org, service in ranges:
        if ip.startswith(prefix):
            return {'org': org, 'service': service}
    return None


# ------------------------------------------------------------------ #
# Reverse DNS lookup                                                  #
# ------------------------------------------------------------------ #

def _reverse_dns(ip: str) -> Optional[str]:
    """Attempt PTR record lookup. Returns hostname or None."""
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host
    except Exception:
        return None


def _org_from_hostname(hostname: str) -> str:
    """
    Infer a human-readable organization name from a reverse-DNS hostname.
    Examples:
      ec2-52-x.compute-1.amazonaws.com  → Amazon AWS
      17-x.apple.com                    → Apple Inc.
      aserver.cdn.cloudflare.net        → Cloudflare
    """
    h = hostname.lower()
    patterns = [
        ('amazonaws.com',      'Amazon AWS'),
        ('awsglobalaccelerator', 'Amazon AWS'),
        ('apple.com',          'Apple Inc.'),
        ('icloud.com',         'Apple iCloud'),
        ('google.com',         'Google LLC'),
        ('googleapis.com',     'Google APIs'),
        ('googleusercontent',  'Google Cloud'),
        ('1e100.net',          'Google LLC'),
        ('cloudflare.com',     'Cloudflare'),
        ('cloudflare.net',     'Cloudflare'),
        ('akamai',             'Akamai Technologies'),
        ('akamaitechnologies', 'Akamai Technologies'),
        ('fastly.net',         'Fastly CDN'),
        ('telegram.org',       'Telegram'),
        ('facebook.com',       'Meta Platforms'),
        ('fbcdn.net',          'Meta / Facebook CDN'),
        ('whatsapp.net',       'Meta / WhatsApp'),
        ('instagram.com',      'Meta / Instagram'),
        ('microsoft.com',      'Microsoft'),
        ('azure.com',          'Microsoft Azure'),
        ('office365.com',      'Microsoft Office 365'),
        ('github.com',         'GitHub'),
        ('github.io',          'GitHub'),
        ('githubusercontent',  'GitHub'),
        ('netflix.com',        'Netflix'),
        ('nflxvideo.net',      'Netflix CDN'),
        ('spotify.com',        'Spotify'),
        ('zoom.us',            'Zoom Video'),
        ('slack.com',          'Slack'),
        ('digitalocean.com',   'DigitalOcean'),
        ('linode.com',         'Linode / Akamai'),
        ('vultr.com',          'Vultr'),
        ('hetzner.com',        'Hetzner'),
        ('ovhcloud.com',       'OVHcloud'),
    ]
    for pattern, name in patterns:
        if pattern in h:
            return name
    # Extract domain from hostname as fallback
    parts = hostname.rstrip('.').split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return hostname


# ------------------------------------------------------------------ #
# API lookup (ip-api.com — free, no key)                             #
# ------------------------------------------------------------------ #

def _rate_limited_get(url: str) -> Optional[dict]:
    global _last_request_ts
    with _request_lock:
        now = time.time()
        gap = now - _last_request_ts
        if gap < MIN_REQUEST_GAP:
            time.sleep(MIN_REQUEST_GAP - gap)
        _last_request_ts = time.time()
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'NetWatch-AnomalyDetector/1.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        logger.debug("HTTP GET failed (%s): %s", url, e)
        return None


def _api_lookup(ip: str) -> Optional[dict]:
    """
    Query ip-api.com. Returns structured dict or None.
    Falls back to reverse DNS if API fails.
    """
    url  = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,org,isp,as,hosting"
    data = _rate_limited_get(url)

    if data and data.get('status') == 'success':
        org     = data.get('org') or data.get('isp') or ''
        country = data.get('country', '')
        city    = data.get('city', '')
        region  = data.get('regionName', '')
        cc      = data.get('countryCode', '').upper()
        is_hosting = data.get('hosting', False)
        flag    = ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc) if len(cc) == 2 else ''

        location_parts = [p for p in [city, region, country] if p]
        location = ', '.join(location_parts[:2])

        label_parts = [p for p in [location, org] if p]
        label = ' · '.join(label_parts) if label_parts else ip

        return {
            'ip':         ip,
            'org':        org or 'Unknown Organization',
            'service':    'Hosting / Cloud' if is_hosting else '',
            'country':    country,
            'region':     region,
            'city':       city,
            'isp':        data.get('isp', ''),
            'asn':        data.get('as', ''),
            'type':       'HOSTING' if is_hosting else 'EXTERNAL',
            'flag':       flag,
            'label':      label,
            'is_local':   False,
            'is_private': False,
            'source':     'ip-api',
        }
    return None


def _dns_lookup(ip: str) -> dict:
    """
    Last resort: reverse DNS + hostname pattern matching.
    Always returns a valid dict (never fails).
    """
    hostname = _reverse_dns(ip)
    org      = _org_from_hostname(hostname) if hostname else 'Unknown Organization'
    short    = hostname.split('.', 1)[1] if hostname and '.' in hostname else hostname

    return {
        'ip':         ip,
        'org':        org,
        'service':    '',
        'country':    '',
        'region':     '',
        'city':       '',
        'isp':        '',
        'asn':        '',
        'type':       'EXTERNAL',
        'flag':       '',
        'label':      f"{org}" + (f" ({short})" if short and short != org else ''),
        'is_local':   False,
        'is_private': False,
        'source':     'rdns' if hostname else 'unknown',
        'hostname':   hostname or '',
    }


# ------------------------------------------------------------------ #
# Public API                                                          #
# ------------------------------------------------------------------ #

def lookup(ip: str) -> dict:
    """
    Full resolution pipeline for a single IP.
    Always returns a valid intel dict — never raises.

    Resolution order:
      1. Cache
      2. This device
      3. Private / special ranges
      4. Known service ranges (hardcoded)
      5. ip-api.com geolocation
      6. Reverse DNS fallback
      7. Bare unknown fallback
    """
    if not ip or ip in ('—', '', None):
        return _bare(ip or '—')

    # 1. Cache hit
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    result = None

    # 2. This device
    if ip in LOCAL_IPS:
        result = {
            'ip':         ip,
            'org':        'This Device',
            'service':    'Local Machine',
            'country':    '',
            'region':     '',
            'city':       '',
            'isp':        'localhost',
            'asn':        '',
            'type':       'LOCAL',
            'flag':       '',
            'label':      'This Device',
            'is_local':   True,
            'is_private': False,
            'source':     'local',
            'hostname':   socket.gethostname(),
        }

    # 3. Private / special ranges
    if result is None:
        m = _match_ranges(ip, PRIVATE_RANGES)
        if m:
            result = {
                'ip':         ip,
                'org':        m['org'],
                'service':    m['service'],
                'country':    '',
                'region':     '',
                'city':       '',
                'isp':        'Private',
                'asn':        '',
                'type':       'PRIVATE',
                'flag':       '',
                'label':      f"{m['org']} — {m['service']}",
                'is_local':   False,
                'is_private': True,
                'source':     'local_range',
                'hostname':   '',
            }

    # 4. Known service ranges
    if result is None:
        m = _match_ranges(ip, KNOWN_RANGES)
        if m:
            result = {
                'ip':         ip,
                'org':        m['org'],
                'service':    m['service'],
                'country':    'US',
                'region':     '',
                'city':       '',
                'isp':        m['org'],
                'asn':        '',
                'type':       'KNOWN_SERVICE',
                'flag':       '',
                'label':      f"{m['org']} — {m['service']}",
                'is_local':   False,
                'is_private': False,
                'source':     'known_range',
                'hostname':   '',
            }

    # 5. ip-api.com for truly unknown external IPs
    if result is None:
        result = _api_lookup(ip)

    # 6. Reverse DNS fallback if API failed
    if result is None:
        result = _dns_lookup(ip)

    # Cache and return
    with _cache_lock:
        _cache[ip] = result
    return result


def _bare(ip: str) -> dict:
    """Absolute fallback — returns a minimal valid record."""
    return {
        'ip':         ip,
        'org':        'Unknown',
        'service':    '',
        'country':    '',
        'region':     '',
        'city':       '',
        'isp':        '',
        'asn':        '',
        'type':       'UNKNOWN',
        'flag':       '',
        'label':      'Unknown',
        'is_local':   False,
        'is_private': False,
        'source':     'unknown',
        'hostname':   '',
    }


def lookup_async(ip: str, callback) -> None:
    """Non-blocking lookup — calls callback(intel_dict) when done."""
    def _run():
        try:
            callback(lookup(ip))
        except Exception as e:
            logger.debug("IP intel callback error: %s", e)
    threading.Thread(target=_run, daemon=True).start()


def get_local_ips() -> set:
    return LOCAL_IPS


def get_cache() -> dict:
    with _cache_lock:
        return dict(_cache)

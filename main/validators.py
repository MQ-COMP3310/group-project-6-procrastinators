import re
import ipaddress
import urllib.request
import urllib.error
from urllib.parse import urlparse
from django.core.exceptions import ValidationError


# Allowed URL schemes: deny javascript:, file://, ftp://, data: etc, Section 8.1.2
ALLOWED_URL_SCHEMES = {'https', 'http'}

# Allowed image file extensions (not trusted alone - magic bytes checked too), Section 8.1.2
ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'}

# Magic bytes for each allowed image format, Section 8.1.2
# Trusting extension/content-type alone is insecure (can be spoofed)
MAGIC_BYTES = {
    b'\xff\xd8\xff':        'JPEG',
    b'\x89PNG\r\n\x1a\n':  'PNG',
    b'GIF87a':              'GIF',
    b'GIF89a':              'GIF',
    b'RIFF':                'WEBP',
    b'BM':                  'BMP',
}

# Maximum image size to prevent DoS via infeasibly large images, Section 8.1.2
MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB

# Maximum field lengths, Section 8.1.2
MAX_MOVIE_NAME_LEN  = 250
MAX_DIRECTOR_LEN    = 300
MAX_CAST_LEN        = 300
MAX_DESCRIPTION_LEN = 5000
MAX_COMMENT_LEN     = 1000

# Private/reserved IP ranges for SSRF blocklist, Section 8.1.2
PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def validate_image_url_scheme(url):
    # Deny insecure web protocols; accept https:// and optionally http:// only, Section 8.1.2
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise ValidationError(
            f"URLs must use http or https. '{parsed.scheme}' is not permitted."
        )


def validate_no_private_ip(url):
    # Do not fetch private resources from inside the system, Section 8.1.2
    import socket
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValidationError("URL does not contain a valid hostname.")
    if hostname.lower() in ('localhost', 'localhost.localdomain'):
        raise ValidationError("URLs pointing to internal resources are not permitted.")
    try:
        results = socket.getaddrinfo(hostname, None)
        for result in results:
            ip_str = result[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            for network in PRIVATE_IP_NETWORKS:
                if ip_obj in network:
                    raise ValidationError(
                        "URLs pointing to internal or private network addresses are not permitted."
                    )
    except ValidationError:
        raise
    except Exception:
        raise ValidationError("The URL hostname could not be resolved.")


def validate_image_magic_bytes(data):
    # Do not trust file extension or Content-Type header, Section 8.1.2
    # e.g. renaming virus.exe to virus.jpg without changing the file
    for magic, fmt in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            if fmt == 'WEBP' and data[8:12] != b'WEBP':
                continue
            return
    raise ValidationError(
        "The URL does not point to a recognised image file. "
        "Accepted formats: JPEG, PNG, GIF, WEBP, BMP."
    )


def validate_image_size(data):
    # Place limits upon external resource size to prevent DoS, Section 8.1.2
    if len(data) > MAX_IMAGE_BYTES:
        raise ValidationError(
            f"Image exceeds the maximum permitted size of {MAX_IMAGE_BYTES // (1024 * 1024)} MB."
        )


def fetch_and_validate_image_url(url):
    # Combines all URL-based image validations, Section 8.1.2:
    # 1. Scheme must be http/https
    # 2. Hostname must not resolve to private IP (SSRF prevention)
    # 3. Content must not exceed size limit
    # 4. Content must have valid image magic bytes
    validate_image_url_scheme(url)
    validate_no_private_ip(url)
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'MovieReview-ImageValidator/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = response.read(MAX_IMAGE_BYTES + 1)
    except urllib.error.URLError as exc:
        raise ValidationError(f"Could not fetch the image URL: {exc.reason}")
    except Exception as exc:
        raise ValidationError(f"Image URL validation failed: {exc}")
    validate_image_size(data)
    validate_image_magic_bytes(data)


def validate_movie_name(value):
    # Maximum sizes for data input, Section 8.1.2
    if len(value) > MAX_MOVIE_NAME_LEN:
        raise ValidationError(f"Movie name must not exceed {MAX_MOVIE_NAME_LEN} characters.")


def validate_description(value):
    # Maximum sizes for data input, Section 8.1.2
    if len(value) > MAX_DESCRIPTION_LEN:
        raise ValidationError(f"Description must not exceed {MAX_DESCRIPTION_LEN} characters.")


def validate_comment(value):
    # Maximum sizes for data input, Section 8.1.2
    if len(value) > MAX_COMMENT_LEN:
        raise ValidationError(f"Comment must not exceed {MAX_COMMENT_LEN} characters.")


def validate_rating(value):
    # Server-side validation only: HTML min/max can be bypassed via browser Inspector, Section 8.1.2
    if value is not None and not (1 <= value <= 10):
        raise ValidationError("Rating must be between 1 and 10.")


def validate_no_script_tag(value):
    # Validate and sanitise vectors for XSS attacks, Section 8.1.2
    if re.search(r'<\s*script', value, re.IGNORECASE):
        raise ValidationError("Input must not contain script tags.")


# HTML entity encoding for XSS prevention, Section 8.1.2
# Django templates auto-escape by default; this is for any context bypassing auto-escape
_HTML_ESCAPE_TABLE = str.maketrans({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;',
})


def sanitize_html_entities(value):
    # Validate and sanitise vectors for XSS attacks, Section 8.1.2
    if not isinstance(value, str):
        value = str(value)
    return value.translate(_HTML_ESCAPE_TABLE)

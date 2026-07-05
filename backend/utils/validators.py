import re
import ipaddress

def is_valid_ip(ip_str):
    """Verifies if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_subnet(subnet_str):
    """Verifies if a string is a valid IPv4 or IPv6 network/subnet (CIDR representation)."""
    try:
        ipaddress.ip_network(subnet_str, strict=False)
        return True
    except ValueError:
        return False

def is_valid_username(username):
    """Checks if username matches valid alphanumeric pattern between 3 and 50 characters."""
    if not username:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]{3,50}$', username))

def is_valid_port(port):
    """Validates if port is a valid port integer (1-65535) or None."""
    if port is None:
        return True
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False

def sanitize_string(val):
    """Trims and strips HTML tags from input string to mitigate persistent/reflected XSS."""
    if not isinstance(val, str):
        return val
    # Remove HTML tags using simple regex
    clean = re.sub(r'<[^>]*>', '', val)
    return clean.strip()

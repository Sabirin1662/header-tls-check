#!/usr/bin/env python3
"""Security header, cookie flag and TLS checker."""
import sys
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Limits what resources the page can load (XSS defence)",
    "Strict-Transport-Security": "Forces HTTPS for future visits (HSTS)",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Stops MIME-type sniffing",
    "Referrer-Policy": "Controls how much referrer info is sent",
}


def check_headers(url):
    """Fetch the URL and report which security headers are present or missing."""
    resp = requests.get(url, timeout=10)
    print(f"\n[Security headers] for {url}")
    for header, description in SECURITY_HEADERS.items():
        if header in resp.headers:
            print(f"  [+] {header}: present")
        else:
            print(f"  [-] {header}: MISSING  ({description})")
    return resp


def check_cookies(resp):
    """Check cookies in the response for Secure, HttpOnly and SameSite flags."""
    print("\n[Cookies]")
    cookies = resp.raw.headers.getlist("Set-Cookie")
    if not cookies:
        print("  No cookies set by this response.")
        return
    for cookie in cookies:
        name = cookie.split("=", 1)[0]
        lowered = cookie.lower()
        secure = "secure" in lowered
        httponly = "httponly" in lowered
        samesite = "samesite" in lowered
        print(f"  Cookie '{name}':")
        print(f"    Secure:   {'[+] yes' if secure else '[-] NO'}")
        print(f"    HttpOnly: {'[+] yes' if httponly else '[-] NO'}")
        print(f"    SameSite: {'[+] yes' if samesite else '[-] NO'}")


def check_tls(url):
    """Connect over TLS and report the protocol version and certificate expiry."""
    print("\n[TLS]")
    host = urlparse(url).hostname
    if not host:
        print("  Could not parse hostname.")
        return
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            version = ssock.version()
            cert = ssock.getpeercert()
    print(f"  Protocol: {version}")
    if version in ("TLSv1", "TLSv1.1"):
        print("    [-] Outdated TLS version in use")
    else:
        print("    [+] Modern TLS version")
    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days_left = (expires.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    print(f"  Certificate expires: {expires.date()} ({days_left} days left)")
    if days_left < 30:
        print("    [-] Certificate expires soon")
    else:
        print("    [+] Certificate validity OK")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 header_tls_check.py <url>")
        sys.exit(1)
    target = sys.argv[1]
    response = check_headers(target)
    check_cookies(response)
    check_tls(target)

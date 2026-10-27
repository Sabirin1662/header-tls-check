# header-tls-check

A small command-line tool that checks a website's HTTP security posture:
security headers, cookie flags, and the TLS configuration. It automates the
manual checks a tester would otherwise run by hand during a web assessment.

## What it checks

Security headers - reports whether these response headers are present:
- Content-Security-Policy (limits what the page can load - XSS defence)
- Strict-Transport-Security (forces HTTPS - HSTS)
- X-Frame-Options (clickjacking protection)
- X-Content-Type-Options (stops MIME sniffing)
- Referrer-Policy (controls referrer leakage)

Cookie flags - for each cookie the server sets, reports whether Secure,
HttpOnly and SameSite are set.

TLS - reports the negotiated TLS protocol version and the certificate's expiry
date, flagging outdated protocols and certificates nearing expiry.

## Requirements

- Python 3
- requests (pip install requests)

## Usage

    python3 header_tls_check.py <url>

Example:

    python3 header_tls_check.py https://github.com

## Example output

See screenshots/example-run.png for a sample run.

    [Security headers] for https://github.com
      [+] Content-Security-Policy: present
      [+] Strict-Transport-Security: present

    [Cookies]
      Cookie '_octo':
        Secure:   [+] yes
        HttpOnly: [-] NO
        SameSite: [+] yes

    [TLS]
      Protocol: TLSv1.3
        [+] Modern TLS version
      Certificate expires: 2026-11-29 (33 days left)
        [+] Certificate validity OK

## Notes

Point this only at systems you own or are authorised to test. It makes a single
normal HTTPS request and one TLS handshake - it does not attack the target.

## About

Built as a portfolio project by a second-year cybersecurity student to
demonstrate practical Python scripting for security assessment.

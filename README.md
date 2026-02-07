# WAFPierce
**CloudFront WAF Bypass & Penetration Testing Tool**

![Version](https://img.shields.io/badge/version-1.2-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

![promotion image](promotion1.png)

## What is WAFPierce?

WAFPierce is a WAF/CDN assessment and bypass validation tool for penetration testing and security research.
It fingerprints 17+ WAF vendors and 12+ CDN providers, then tests 35+ bypass/evasion techniques using baseline + heuristic comparisons (status codes, response size, hashes) to confirm real bypasses—even when defenses return  OK.
It also supports rate-limit detection, API endpoint and directory discovery, protocol-level testing (request smuggling, HTTP/2 downgrade, WebSocket tunneling), injection payload testing (SQLi, XSS, SSRF, traversal, command injection), AWS recon (related S3 buckets), a clean GUI, optimized parallel performance, and automated Markdown reporting.

**Key Features:**
- **WAF Detection & Fingerprinting** - Identifies 17+ WAF vendors (Cloudflare, AWS WAF, Akamai, Imperva, F5, Sucuri, ModSecurity, and more)
- **CDN Detection** - Detects 12+ CDN providers (CloudFront, Akamai, Fastly, Cloudflare, etc.)
- **WAF Bypass Detection** - Tests 35+ different bypass techniques
- **Smart WAF Bypass** - Uses baseline comparison and heuristic analysis (size, hash, status codes) to detect bypasses even when WAFs return 200 OK.
- **Payload Evasion Testing** - SQLi, XSS, Command Injection, Path Traversal, SSRF bypass payloads
- **Protocol-Level Attacks** - HTTP Request Smuggling, HTTP/2 Downgrade, WebSocket tunneling
- **Rate Limit Detection** - Identifies request thresholds and rate limiting behavior
- **API Endpoint Discovery** - Finds unprotected API routes and debug endpoints
- **Directory Enumeration** - Discovers hidden paths using successful bypass methods
- **Vulnerability Scanning** - Tests for XSS and injection points
- **AWS Reconnaissance** - Enumerates related S3 buckets
- **Automated Reporting** - Generates detailed markdown reports
- **GUI system** - Clean and efficient GUI system made for the users comfort  
- **Optimized Performance** - Connection pooling, response caching, and parallel batch testing

## Changelog

### Version 1.2 (February 2026)

#### GUI Enhancements
- **Results Explorer** - New comprehensive results viewer with:
  - Left panel showing all scanned sites with finding counts and severity indicators (🔴🟠🟡)
  - "All Sites" option to view combined results across all targets
  - Results grouped by category (API_DISCOVERY, DNS_HISTORY, etc.)
  - Detailed view panel showing full result information when clicked
  - **Sorting options**: Severity (High→Low, Low→High), Technique (A-Z, Z-A), Category, Bypass Status
  - **Filtering options**: All Results, CRITICAL/HIGH/MEDIUM/LOW/INFO only, Bypasses only, Non-bypasses only
  - Expand All / Collapse All buttons for quick navigation
  - Export View button to save filtered results to JSON

- **Pulsating Results Button** - The Results button now:
  - Located at the bottom of the output area for better visibility
  - Larger size (40px height) with 📊 icon
  - Turns **green** and gently **pulsates** when scan completes with results
  - Changes color on hover (darkens) for better interactivity
  - Resets to default gray when results are cleared

- **INFO-Level Results** - All scan results now appear in output, not just bypasses:
  - LOW and INFO severity findings are now displayed
  - Shows reason for blocked requests (e.g., "Blocked: 404")
  - Complete visibility into all scan activity

- **Target Tracking** - Results Explorer now shows actual target site names instead of "Unknown Target"

#### Technical Improvements
- Fixed result filtering to include all findings (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Added target URL injection into result objects for proper grouping
- Improved URL parsing to extract clean domain names for display
- Added QPropertyAnimation for smooth pulsating effects
- Better stylesheet management with hover states

## Installation

```bash
# Clone repository
git clone https://github.com/K0NGR3SS/WAFPierce.git
cd WAFPierce

# Install dependencies
pip3 install -r requirements.txt

# Install in development mode
pip3 install -e .
```

## Usage

### Run UI
```bash
python3 -m wafpierce.gui  
```

### Basic Scan
```bash
wafpierce https://d123abc.cloudfront.net
```

### Advanced Options
```bash
# Specify threads
wafpierce https://target.cloudfront.net -t 20

# Custom output directory
wafpierce https://target.cloudfront.net -o my_results
```

### Standalone WAF Bypass Scanner
```bash
# Run just the bypass scanner
python3 -m wafpierce.pierce https://target.cloudfront.net -t 10
```

## Bypass Techniques

WAFPierce tests the following bypass methods:

### Header Manipulation
1. **Host Header Injection** - Manipulates Host header values
2. **X-Forwarded-For** - IP spoofing via proxy headers (127.0.0.1, 10.x, 192.168.x, AWS metadata IP)
3. **X-Forwarded-Host** - Alternative host header injection
4. **X-Original-URL / X-Rewrite-URL** - Path override attempts
5. **Origin/Referer Manipulation** - CORS and origin header bypass
6. **Custom Header Fuzzing** - X-Debug, X-Internal, X-Skip-WAF headers
7. **True-Client-IP / CF-Connecting-IP** - CDN-specific header spoofing

### Encoding & Obfuscation
8. **Path Encoding** - URL encoding bypasses (%2e, %252e, etc.)
9. **Double/Triple Encoding** - Advanced encoding evasion
10. **Case Manipulation** - Mixed case payloads (/AdMiN, /WP-ADMIN)
11. **Comment Injection** - SQL/HTML comment insertion
12. **Whitespace Manipulation** - Tabs, newlines, null bytes to break signatures
13. **Unicode Normalization** - Unicode encoding tricks

### Protocol-Level Attacks
14. **Transfer-Encoding Smuggling** - CL.TE/TE.TE request smuggling
15. **HTTP/2 Downgrade** - Protocol downgrade attacks
16. **WebSocket Upgrade** - Tunnel through WAFs via WebSocket
17. **HTTP Pipelining** - Connection keep-alive abuse
18. **Chunked Transfer** - Split payloads across chunks
19. **HTTP Method Bypass** - Tests non-standard methods (TRACE, OPTIONS, PUT, DELETE)
20. **HTTP Method Override** - X-HTTP-Method-Override header manipulation
21. **Advanced Request Smuggling** - H2.CL, H2.TE, TE.TE variations, HTTP/3 downgrade attempts

### Cache & Control
22. **Cache-Control** - Cache directive manipulation
23. **Cache Poisoning** - Unkeyed header injection (X-Forwarded-Host, X-Original-URL)
24. **Range Header** - Partial content bypasses

### Payload Evasion
25. **SQLi Bypass** - WAF-evading SQL injection payloads (comment obfuscation, case variation, encoding)
26. **XSS Bypass** - Cross-site scripting evasion (tag manipulation, event handlers, encoding)
27. **Command Injection Bypass** - OS command injection evasion (IFS, encoding, chaining)
28. **Path Traversal Bypass** - Directory traversal evasion (encoding, null bytes, normalization)
29. **SSRF Bypass** - Server-side request forgery evasion (IP formats, DNS rebinding, protocol smuggling)
30. **HTTP Parameter Pollution** - Duplicate parameters to confuse parsing
31. **Polyglot Payloads** - Multi-context payloads (XSS+SQLi, SSTI+XSS, universal escapes)
32. **Payload Mutation Engine** - Automated payload variations (case, encoding, unicode, whitespace)
33. **GraphQL Bypass** - GraphQL introspection, batching, and complexity abuse
34. **JWT/OAuth Bypass** - Token manipulation (algorithm confusion, null signature, KID injection, scope escalation)
35. **Time-Based Blind Detection** - Response timing analysis for SQL injection and WAF processing delays
36. **Race Condition Testing** - Concurrent requests to exploit timing windows

### Detection & Reconnaissance
37. **WAF Fingerprinting** - Identifies WAF vendor and version (Cloudflare, AWS WAF, Akamai, Imperva, F5, Sucuri, ModSecurity, Barracuda, Fortinet, and 20+ more)
38. **WAF Rule Version Detection** - Identifies OWASP CRS version and active rule IDs
39. **JavaScript WAF Detection** - Detects client-side protection (PerimeterX, DataDome, HUMAN Security, Kasada, Shape Security, Distil)
40. **CDN Detection** - Identifies CDN provider (CloudFront, Akamai, Fastly, Cloudflare, etc.)
41. **Rate Limit Detection** - Identifies request thresholds and rate limiting headers
42. **Bot Detection Evasion** - User-Agent rotation, browser fingerprint simulation (Googlebot, legitimate browsers)
43. **API Endpoint Discovery** - Finds unprotected /api/, /graphql, /swagger, /actuator, /health endpoints
44. **IPv6 Bypass** - Direct IPv6 connection attempts to bypass IPv4-only WAF rules
45. **Content-Type Bypass** - MIME type confusion attacks
46. **Subdomain Enumeration** - Discovers subdomains (www, api, dev, staging, admin) via DNS resolution
47. **Certificate Transparency Lookup** - Extracts domains from SSL certificate SANs
48. **Historical DNS Lookup** - Finds origin IPs via DNS history to bypass CDN/WAF
49. **Cloud Metadata Enumeration** - Tests SSRF to cloud IMDS endpoints (AWS, GCP, Azure) for credential exposure
50. **Technology Stack Fingerprinting** - Identifies frameworks (Django, Rails, Laravel), CMS (WordPress, Drupal), servers (nginx, Apache), and exposed config files


## Requirements

- Python 3.8+
- PySide6 6.10.1+
- requests library

## Responsible Disclosure

If you discover vulnerabilities using this tool:
1. **DO** report to the affected organization immediately
2. **DO** give reasonable time for fixes (typically 90 days)
3. **DO** follow coordinated disclosure practices
4. **DON'T** publicly disclose until patched
5. **DON'T** exploit findings for personal gain

## Educational Resources

This tool is designed for learning. Recommended resources:
- [OWASP WAF Testing Guide](https://owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Bug Bounty Platforms](https://www.hackerone.com/) (for authorized testing)

## Authors

- Nazariy Buryak
- Marwan Fayad

## Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is intended exclusively for authorized penetration testing and security research. You must obtain explicit written permission before testing any system you do not own.

**Unauthorized access to computer systems is illegal.** Violators may face prosecution under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, or equivalent laws in your jurisdiction.

By using this tool, you agree to:
- Only test systems you own or have written authorization to test
- Comply with all applicable laws and regulations
- Accept full responsibility for your actions

The authors assume **NO LIABILITY** for misuse. This software is provided "AS IS" without warranty of any kind.

**If you don't have permission, don't use it.**









#### There are hidden things in this program, can you find them all?

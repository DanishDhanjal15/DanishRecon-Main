#!/usr/bin/env python3
"""
API Scanner Module - Advanced API Endpoint Discovery & Vulnerability Scanning
Integrates with DanishRecon for discovering APIs and checking for vulnerabilities
"""

import requests
import json
import re
import sqlite3
from datetime import datetime
from urllib.parse import urljoin, urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class APIScanner:
    """Advanced API Scanner with authentication support and database integration"""
    
    def __init__(self, db_path, base_url, scan_id, callback=None, deep_mode=False, 
                 auth_bearer=None, auth_cookie=None, auth_surface="public"):
        """
        Initialize API Scanner
        
        Args:
            db_path: Path to SQLite database
            base_url: Target URL to scan
            scan_id: Scan ID for database tracking
            callback: Logging callback function
            deep_mode: Enable deep scanning
            auth_bearer: Bearer token for authentication
            auth_cookie: Cookie header for authentication
            auth_surface: Surface name (public/authenticated)
        """
        self.db_path = db_path
        self.base_url = base_url.rstrip('/')
        self.scan_id = scan_id
        self.callback = callback or print
        self.deep_mode = deep_mode
        self.auth_bearer = auth_bearer
        self.auth_cookie = auth_cookie
        self.auth_surface = auth_surface
        
        self.session = requests.Session()
        self.session.verify = False
        self.endpoints = []
        self.vulnerabilities = []
        
        # Common API paths to discover
        self.common_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/graphql', '/graphql/',
            '/.well-known/openapi.json',
            '/swagger-ui.html', '/swagger-ui/', '/swagger-ui/index.html',
            '/api-docs', '/api-docs/', '/docs', '/redoc',
            '/openapi.json', '/openapi.yaml', '/swagger.json', '/swagger.yaml',
            '/specification', '/admin/api', '/api/admin',
            '/api/auth', '/api/users', '/api/products', '/api/orders',
            '/api/login', '/api/register', '/api/logout',
            '/api/profile', '/api/settings', '/api/search', '/api/info',
            '/api/health', '/api/status', '/api/version',
            '/.well-known/configuration.json', '/config.json',
        ]
        
        # Setup authentication headers if provided
        self._setup_auth_headers()
    
    def _setup_auth_headers(self):
        """Configure request headers with authentication"""
        if self.auth_bearer:
            self.session.headers.update({'Authorization': f'Bearer {self.auth_bearer}'})
        if self.auth_cookie:
            self.session.headers.update({'Cookie': self.auth_cookie})
    
    def _log(self, message, level="info"):
        """Log message with level"""
        if self.callback:
            self.callback(f"  {message}", level)
    
    def discover_endpoints(self):
        """Discover API endpoints"""
        self._log(f"Discovering API endpoints on {self.base_url}", "info")
        
        for path in self.common_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code < 400:
                    endpoint = {
                        'url': url,
                        'path': path,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'method': 'GET',
                        'auth_surface': self.auth_surface,
                        'timestamp': datetime.now().isoformat(),
                        'discovery_source': 'path-list',
                        'content_type': response.headers.get('content-type', ''),
                    }
                    
                    # Detect API type
                    api_type = self._detect_api_type(response)
                    if api_type:
                        endpoint['type'] = api_type
                        self.endpoints.append(endpoint)
                        self._log(f"Found API endpoint: {path} ({api_type})", "good")
                        
            except Exception as e:
                pass
        
        return self.endpoints
    
    def _detect_api_type(self, response):
        """Detect API type from response"""
        try:
            content_type = response.headers.get('content-type', '').lower()
            
            if 'application/json' in content_type:
                try:
                    data = response.json()
                    if 'swagger' in str(data).lower() or 'openapi' in str(data).lower():
                        return 'OpenAPI/Swagger'
                    if isinstance(data, dict):
                        if any(k in data for k in ['query', 'mutations', '__schema']):
                            return 'GraphQL'
                    return 'JSON API'
                except:
                    pass
            
            if 'text/html' in content_type:
                if 'swagger' in response.text.lower():
                    return 'Swagger UI'
                if 'redoc' in response.text.lower():
                    return 'ReDoc'
            
            return None
        except:
            return None
    
    def check_api_vulnerabilities(self):
        """Check for common API vulnerabilities"""
        self._log("Checking for API vulnerabilities", "info")
        
        for endpoint in self.endpoints:
            url = endpoint['url']
            
            # Check for CORS issues
            try:
                response = self.session.get(url, timeout=5)
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                if cors_header == '*':
                    vuln = {
                        'url': url,
                        'type': 'CORS Misconfiguration',
                        'severity': 'MEDIUM',
                        'description': 'Allows requests from any origin'
                    }
                    self.vulnerabilities.append(vuln)
                    self._log(f"CORS misconfiguration detected on {url}", "warn")
            except:
                pass
            
            # Check for missing authentication.
            # These endpoints are already in self.endpoints because they returned < 400
            # during discovery. If a *sensitive* endpoint responded successfully on the
            # public surface (no auth supplied), that's a potential broken-auth issue.
            if endpoint.get('auth_surface', 'public') == 'public':
                url_l = url.lower()
                sensitive_markers = ['/auth', '/login', '/token', '/admin', '/users',
                                     '/account', '/profile', '/settings']
                if any(marker in url_l for marker in sensitive_markers):
                    vuln = {
                        'url': url,
                        'type': 'Potentially Unauthenticated API',
                        'severity': 'HIGH',
                        'description': 'Sensitive API endpoint responded on the public surface without authentication'
                    }
                    self.vulnerabilities.append(vuln)
                    self._log(f"Potential auth issue on {url}", "warn")
        
        return self.vulnerabilities
    
    def scan(self):
        """Run full API scan"""
        self._log(f"Starting API scan ({self.auth_surface} surface)", "info")
        
        # Discover endpoints
        self.discover_endpoints()
        
        # Check vulnerabilities only if endpoints were found and deep mode is on
        # Wrapped in try/except so a vuln-check crash never discards found endpoints
        if self.deep_mode and self.endpoints:
            try:
                self.check_api_vulnerabilities()
            except Exception as e:
                self._log(f"API vulnerability check error (non-fatal): {e}", "warn")
        
        # Store results in database
        self._store_results()
        
        return {
            'endpoints': self.endpoints,
            'vulnerabilities': self.vulnerabilities,
            'total_endpoints': len(self.endpoints),
            'total_vulnerabilities': len(self.vulnerabilities)
        }
    
    def _store_results(self):
        """Store scan results in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            for endpoint in self.endpoints:
                # Use correct column names matching the actual DB schema:
                # auth_surface (not surface), found_at (not discovered_at)
                c.execute("""
                    INSERT OR IGNORE INTO api_endpoints 
                    (scan_id, url, path, status_code, api_type, auth_surface, found_at,
                     source_url, response_headers, method)
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?)
                """, (
                    self.scan_id,
                    endpoint['url'],
                    endpoint['path'],
                    endpoint['status_code'],
                    endpoint.get('type', 'Unknown'),
                    endpoint.get('auth_surface', self.auth_surface),
                    endpoint.get('url', ''),
                    json.dumps(endpoint.get('headers', {}), ensure_ascii=False)[:2000],
                    endpoint.get('method', 'GET'),
                ))
            
            for vuln in self.vulnerabilities:
                c.execute("""
                    INSERT OR IGNORE INTO api_vulnerabilities
                    (scan_id, url, vuln_type, severity, description, discovered_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                """, (
                    self.scan_id,
                    vuln['url'],
                    vuln['type'],
                    vuln['severity'],
                    vuln['description']
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self._log(f"Failed to store API scan results: {e}", "error")
    
    def get_results(self):
        """Get scan results"""
        return {
            'endpoints': self.endpoints,
            'vulnerabilities': self.vulnerabilities,
            'total_endpoints': len(self.endpoints),
            'total_vulnerabilities': len(self.vulnerabilities)
        }

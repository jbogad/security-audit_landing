#!/usr/bin/env python3
"""
HackPrevent Web Vulnerability Scanner - Fixed Version
Professional external security analysis tool
Author: Javier Bogado - HackPrevent
Date: 2025-09-03
"""

import requests
import ssl
import socket
import json
import time
import urllib3
import subprocess
import sys
import os
from urllib.parse import urljoin, urlparse
from datetime import datetime
import argparse
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import traceback

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm
except ImportError:
    print("🚀 Installing required dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                          "beautifulsoup4", "colorama", "tqdm"])
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm

init(autoreset=True)

class HackPreventScanner:
    """Fixed Professional Web Vulnerability Scanner"""
    
    def __init__(self, target_url, threads=10):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.threads = threads
        self.session = requests.Session()
        
        # Configure session with error handling
        self.setup_session()
        
        self.vulnerabilities = []
        self.scan_results = {
            'target': target_url,
            'scan_date': datetime.now().isoformat(),
            'scanner_version': 'HackPrevent Fixed v1.1',
            'vulnerabilities': [],
            'summary': {}
        }
    
    def setup_session(self):
        """Setup session with proper error handling"""
        try:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            })
            
            # Disable SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Set timeouts and retries
            self.session.verify = False
            self.session.timeout = 10
            
        except Exception as e:
            print(f"⚠️  Session setup warning: {e}")
    
    def print_banner(self):
        """Display scanner banner"""
        banner = f"""
{Fore.CYAN}╭{'─' * 70}╮
{Fore.CYAN}│{Fore.YELLOW}  🛡️  HACKPREVENT WEB SCANNER v1.1 - FIXED{' ' * 17}│
{Fore.CYAN}│{Fore.GREEN}  Professional Security Analysis Tool{' ' * 23}│
{Fore.CYAN}│{' ' * 70}│
{Fore.CYAN}│{Fore.WHITE}  🎯 Target: {self.target_url:<50}│
{Fore.CYAN}│{Fore.WHITE}  👤 Operator: jbogad{' ' * 43}│
{Fore.CYAN}│{Fore.WHITE}  📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<50}│
{Fore.CYAN}╰{'─' * 70}╯{Style.RESET_ALL}
        """
        print(banner)
    
    def log_vulnerability(self, vuln_type, severity, description, evidence="", recommendation=""):
        """Log discovered vulnerabilities"""
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        
        # Console output
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
        
        print(f"{color}{emoji} [{severity}] {vuln_type}: {description}{Style.RESET_ALL}")
        if evidence:
            print(f"   🔍 Evidence: {evidence[:80]}...")
    
    def check_connectivity(self):
        """Check target connectivity with robust error handling"""
        print(f"\n{Fore.BLUE}🌐 Checking target connectivity...{Style.RESET_ALL}")
        
        try:
            # First try HEAD request
            response = self.session.head(self.target_url, timeout=15, allow_redirects=True)
            print(f"{Fore.GREEN}✅ HEAD request successful: {response.status_code}")
            
            # Then try GET request
            response = self.session.get(self.target_url, timeout=15, allow_redirects=True)
            server = response.headers.get('server', 'Unknown')
            powered_by = response.headers.get('x-powered-by', 'Unknown')
            
            print(f"{Fore.GREEN}✅ Target is reachable")
            print(f"{Fore.GREEN}✅ Status Code: {response.status_code}")
            print(f"{Fore.GREEN}✅ Server: {server}")
            if powered_by != 'Unknown':
                print(f"{Fore.GREEN}✅ Powered by: {powered_by}")
            
            # Basic tech detection
            self.basic_tech_detection(response)
            
            return True
            
        except requests.exceptions.Timeout:
            self.log_vulnerability("Connectivity", "CRITICAL", "Request timeout - target may be slow or unreachable")
            return False
        except requests.exceptions.ConnectionError as e:
            self.log_vulnerability("Connectivity", "CRITICAL", f"Connection error: {str(e)}")
            return False
        except Exception as e:
            self.log_vulnerability("Connectivity", "CRITICAL", f"Cannot reach target: {str(e)}")
            return False
    
    def basic_tech_detection(self, response):
        """Basic technology detection"""
        print(f"\n{Fore.BLUE}🔍 Basic technology detection...{Style.RESET_ALL}")
        
        try:
            content = response.text.lower()
            headers = response.headers
            
            # Server detection
            server = headers.get('server', '').lower()
            if 'nginx' in server:
                print(f"{Fore.CYAN}🔧 Detected: Nginx Web Server")
            elif 'apache' in server:
                print(f"{Fore.CYAN}🔧 Detected: Apache Web Server")
            elif 'iis' in server:
                print(f"{Fore.CYAN}🔧 Detected: Microsoft IIS")
            
            # PHP detection
            powered_by = headers.get('x-powered-by', '')
            if 'php' in powered_by.lower():
                print(f"{Fore.CYAN}🔧 Detected: {powered_by}")
            
            # CMS detection
            if 'joomla' in content or '/administrator/' in content:
                print(f"{Fore.CYAN}🔧 Detected: Joomla CMS")
            elif 'wordpress' in content or '/wp-content/' in content:
                print(f"{Fore.CYAN}🔧 Detected: WordPress CMS")
            elif 'drupal' in content:
                print(f"{Fore.CYAN}🔧 Detected: Drupal CMS")
            
        except Exception as e:
            print(f"  ⚠️  Tech detection error: {e}")
    
    def security_headers_analysis(self):
        """Security headers analysis with error handling"""
        print(f"\n{Fore.BLUE}🛡️  Analyzing security headers...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target_url, timeout=15)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            security_headers = {
                'strict-transport-security': {
                    'description': 'HTTPS enforcement',
                    'severity': 'HIGH',
                    'recommendation': 'Implement HSTS'
                },
                'content-security-policy': {
                    'description': 'Content injection protection',
                    'severity': 'HIGH', 
                    'recommendation': 'Implement CSP'
                },
                'x-frame-options': {
                    'description': 'Clickjacking protection',
                    'severity': 'MEDIUM',
                    'recommendation': 'Set X-Frame-Options'
                },
                'x-content-type-options': {
                    'description': 'MIME sniffing protection',
                    'severity': 'MEDIUM',
                    'recommendation': 'Set to nosniff'
                },
                'x-xss-protection': {
                    'description': 'XSS protection',
                    'severity': 'MEDIUM',
                    'recommendation': 'Enable XSS protection'
                }
            }
            
            present_count = 0
            total_count = len(security_headers)
            
            for header, info in security_headers.items():
                if header in headers:
                    present_count += 1
                    print(f"{Fore.GREEN}✅ {header}: {headers[header][:50]}...")
                else:
                    self.log_vulnerability("Missing Security Header", info['severity'],
                                         f"Missing {header} header",
                                         f"Header: {header}",
                                         info['recommendation'])
            
            score = (present_count / total_count) * 100
            print(f"{Fore.YELLOW}📊 Security Headers Score: {score:.1f}% ({present_count}/{total_count})")
            
        except Exception as e:
            self.log_vulnerability("Header Analysis", "LOW", f"Header analysis failed: {str(e)}")
    
    def basic_directory_scan(self):
        """Basic directory enumeration"""
        print(f"\n{Fore.BLUE}📁 Basic directory enumeration...{Style.RESET_ALL}")
        
        common_paths = [
            '/admin', '/administrator', '/wp-admin', '/login',
            '/phpmyadmin', '/cpanel', '/config', '/backup',
            '/robots.txt', '/sitemap.xml', '/.git', '/.env',
            '/test', '/dev', '/api', '/upload'
        ]
        
        found_paths = []
        
        for path in common_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    found_paths.append({
                        'path': path,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
                    
                    if response.status_code == 200:
                        print(f"{Fore.GREEN}✅ Found: {path} (Status: {response.status_code})")
                        
                        # Check for sensitive content
                        if path in ['/admin', '/administrator', '/wp-admin', '/login']:
                            self.log_vulnerability("Sensitive Directory", "MEDIUM",
                                                 f"Administrative interface accessible at {path}",
                                                 f"Status: {response.status_code}",
                                                 "Restrict access to administrative interfaces")
                    else:
                        print(f"{Fore.CYAN}ℹ️  {path}: {response.status_code}")
                        
            except Exception:
                continue
        
        print(f"{Fore.GREEN}📋 Found {len(found_paths)} accessible paths")
        return found_paths
    
    def basic_ssl_analysis(self):
        """Basic SSL analysis with error handling"""
        print(f"\n{Fore.BLUE}🔒 Basic SSL/TLS analysis...{Style.RESET_ALL}")
        
        if not self.target_url.startswith('https://'):
            self.log_vulnerability("SSL Configuration", "HIGH", 
                                 "Site not using HTTPS",
                                 "URL scheme: HTTP",
                                 "Implement HTTPS with valid SSL certificate")
            return
        
        try:
            hostname = urlparse(self.target_url).netloc
            port = 443
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    
                    if cert:
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        print(f"{Fore.GREEN}✅ SSL Certificate valid")
                        print(f"{Fore.GREEN}✅ Protocol: {protocol}")
                        print(f"{Fore.GREEN}✅ Expires: {cert['notAfter']} ({days_until_expiry} days)")
                        
                        if days_until_expiry < 30:
                            severity = "HIGH" if days_until_expiry < 7 else "MEDIUM"
                            self.log_vulnerability("SSL Certificate", severity,
                                                 f"Certificate expires in {days_until_expiry} days",
                                                 f"Expires: {cert['notAfter']}",
                                                 "Renew SSL certificate")
                        
                        if protocol in ['TLSv1', 'TLSv1.1']:
                            self.log_vulnerability("SSL Protocol", "MEDIUM",
                                                 f"Weak TLS protocol: {protocol}",
                                                 f"Current: {protocol}",
                                                 "Upgrade to TLS 1.2+")
            
        except Exception as e:
            self.log_vulnerability("SSL Analysis", "LOW", f"SSL analysis failed: {str(e)}")
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(f"\n{Fore.YELLOW}📊 Generating security report...{Style.RESET_ALL}")
        
        # Calculate risk metrics
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        severity_weights = {'CRITICAL': 25, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 1, 'INFO': 0}
        
        total_risk_score = 0
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] += 1
            total_risk_score += severity_weights.get(severity, 0)
        
        # Determine risk level
        if total_risk_score >= 50:
            risk_level = "HIGH"
            risk_color = Fore.RED
            risk_emoji = "🔴"
        elif total_risk_score >= 20:
            risk_level = "MEDIUM"
            risk_color = Fore.YELLOW
            risk_emoji = "🟡"
        elif total_risk_score >= 5:
            risk_level = "LOW"
            risk_color = Fore.CYAN
            risk_emoji = "🔵"
        else:
            risk_level = "MINIMAL"
            risk_color = Fore.GREEN
            risk_emoji = "🟢"
        
        # Update scan results
        self.scan_results.update({
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'risk_score': total_risk_score,
                'risk_level': risk_level,
                'severity_breakdown': severity_counts
            }
        })
        
        # Generate report files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain_clean = self.domain.replace('.', '_')
        report_filename = f"hackprevent_scan_{domain_clean}_{timestamp}.json"
        
        # Save JSON report
        with open(report_filename, 'w') as f:
            json.dump(self.scan_results, f, indent=2, default=str)
        
        # Print summary
        print(f"\n{Fore.CYAN}╭{'─' * 70}╮")
        print(f"{Fore.CYAN}│{Fore.YELLOW}  🛡️  HACKPREVENT SCAN RESULTS{' ' * 29}│")
        print(f"{Fore.CYAN}├{'─' * 70}┤")
        print(f"{Fore.CYAN}│{Fore.WHITE}  🎯 Target: {self.target_url:<50}│")
        print(f"{Fore.CYAN}│{Fore.WHITE}  📅 Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<46}│")
        print(f"{Fore.CYAN}│{' ' * 70}│")
        print(f"{Fore.CYAN}│{risk_color}  {risk_emoji} Risk Level: {risk_level} (Score: {total_risk_score}){' ' * (47-len(risk_level)-len(str(total_risk_score)))}│")
        print(f"{Fore.CYAN}│{' ' * 70}│")
        print(f"{Fore.CYAN}│{Fore.RED}  🔴 Critical: {severity_counts['CRITICAL']:<3} 🟠 High: {severity_counts['HIGH']:<3} 🟡 Medium: {severity_counts['MEDIUM']:<3} 🔵 Low: {severity_counts['LOW']:<8}│")
        print(f"{Fore.CYAN}│{' ' * 70}│")
        print(f"{Fore.CYAN}│{Fore.WHITE}  📄 Report saved: {report_filename:<42}│")
        print(f"{Fore.CYAN}╰{'─' * 70}╯{Style.RESET_ALL}")
        
        return report_filename
    
    def run_scan(self):
        """Execute comprehensive security scan"""
        try:
            self.print_banner()
            
            print(f"{Fore.GREEN}🚀 Starting security assessment...{Style.RESET_ALL}")
            
            # Pre-scan connectivity check
            if not self.check_connectivity():
                print(f"{Fore.RED}❌ Cannot proceed - target unreachable{Style.RESET_ALL}")
                return False
            
            # Run scan modules
            scan_modules = [
                ("Security Headers Analysis", self.security_headers_analysis),
                ("Basic SSL Analysis", self.basic_ssl_analysis),
                ("Directory Enumeration", self.basic_directory_scan)
            ]
            
            for module_name, module_func in scan_modules:
                try:
                    print(f"\n{Fore.BLUE}🔍 Running {module_name}...{Style.RESET_ALL}")
                    module_func()
                    time.sleep(1)  # Rate limiting
                except Exception as e:
                    print(f"{Fore.RED}❌ Error in {module_name}: {str(e)}{Style.RESET_ALL}")
                    self.log_vulnerability("Scan Error", "LOW", f"Error in {module_name}: {str(e)}")
            
            # Generate report
            report_file = self.generate_report()
            
            print(f"\n{Fore.GREEN}✅ Security assessment completed!")
            print(f"{Fore.GREEN}📊 Found {len(self.vulnerabilities)} issues")
            print(f"{Fore.GREEN}📁 Report saved: {report_file}{Style.RESET_ALL}")
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"\n{Fore.RED}❌ Unexpected error: {str(e)}")
            traceback.print_exc()
            return False

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='🛡️  HackPrevent Professional Web Security Scanner - Fixed Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hackprevent_fixed_scanner.py -u https://example.com
  python3 hackprevent_fixed_scanner.py -u https://testsite.com -t 20
  
💼 Professional cybersecurity tool by Javier Bogado - HackPrevent
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='🎯 Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='🔧 Number of threads (default: 10)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}❌ Error: URL must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        # Create and run scanner
        scanner = HackPreventScanner(args.url, args.threads)
        success = scanner.run_scan()
        
        if success:
            print(f"\n{Fore.GREEN}🎉 Scan completed successfully!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}❌ Scan failed{Style.RESET_ALL}")
            sys.exit(1)
        
    except Exception as e:
        print(f"{Fore.RED}❌ Fatal error: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
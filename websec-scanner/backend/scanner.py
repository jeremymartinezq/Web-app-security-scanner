import os
import time
import json
import logging
import threading
import queue
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from dotenv import load_dotenv

from .utils import (
    normalize_url, is_valid_url, is_same_domain, 
    extract_links, extract_forms, detect_login_form,
    calculate_risk_score, generate_payload_for_vulnerability,
    detect_technology, format_scan_duration, logger
)

# Load environment variables
load_dotenv()

# Configuration from environment
HEADLESS_BROWSER = os.getenv("HEADLESS_BROWSER", "True").lower() == "true"
BROWSER_TIMEOUT = int(os.getenv("BROWSER_TIMEOUT", 30))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 10))

class SecurityScanner:
    """Core security scanner class for detecting web vulnerabilities"""
    
    def __init__(self, db_session=None):
        self.db_session = db_session
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.results = []
        self.scan_id = None
        self.scan_depth = 1
        self.include_subdomains = False
        self.base_domain = None
        self.base_url = None
        self.start_time = None
        self.browser = None
        self.active = False
        self.vulnerability_count = 0
        self.config = {}
        
    def _setup_browser(self):
        """Set up Selenium browser for scanning"""
        try:
            chrome_options = Options()
            if HEADLESS_BROWSER:
                chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-notifications")
            chrome_options.add_argument("--ignore-certificate-errors")
            
            service = Service(ChromeDriverManager().install())
            browser = webdriver.Chrome(service=service, options=chrome_options)
            browser.set_page_load_timeout(BROWSER_TIMEOUT)
            return browser
        except Exception as e:
            logger.error(f"Failed to setup browser: {str(e)}")
            return None
            
    def start_scan(self, url, scan_depth=1, include_subdomains=False, config=None):
        """Start a security scan on the specified URL"""
        if not is_valid_url(url):
            logger.error(f"Invalid URL provided: {url}")
            return {"error": "Invalid URL provided"}
            
        self.active = True
        self.start_time = time.time()
        self.scan_depth = scan_depth
        self.include_subdomains = include_subdomains
        self.base_url = normalize_url(url)
        self.base_domain = urlparse(self.base_url).netloc
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.results = []
        self.vulnerability_count = 0
        
        # Default or custom scan configuration
        default_config = {
            "check_sql_injection": True,
            "check_xss": True,
            "check_csrf": True,
            "check_ssrf": True,
            "check_xxe": True,
            "check_auth": True,
            "max_urls_to_scan": 100,
            "request_timeout": REQUEST_TIMEOUT
        }
        self.config = {**default_config, **(config or {})}
        
        # Set up browser
        self.browser = self._setup_browser()
        if not self.browser:
            return {"error": "Failed to initialize browser"}
        
        # Add base URL to queue
        self.url_queue.put((self.base_url, 0))  # (url, depth)
        
        # Create scan record in database if session provided
        if self.db_session:
            from .database import ScanTarget
            scan_target = ScanTarget(
                url=self.base_url,
                status="in_progress",
                scan_depth=scan_depth
            )
            self.db_session.add(scan_target)
            self.db_session.commit()
            self.scan_id = scan_target.id
            
        # Start crawling
        try:
            self._crawl_site()
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            self.active = False
            if self.browser:
                self.browser.quit()
                
            # Update scan status if database available
            if self.db_session and self.scan_id:
                from .database import ScanTarget
                scan_target = self.db_session.query(ScanTarget).get(self.scan_id)
                if scan_target:
                    scan_target.status = "failed"
                    self.db_session.commit()
            
            return {"error": f"Scan failed: {str(e)}"}
            
        # Finalize scan
        scan_duration = time.time() - self.start_time
        
        # Update scan status if database available
        if self.db_session and self.scan_id:
            from .database import ScanTarget
            scan_target = self.db_session.query(ScanTarget).get(self.scan_id)
            if scan_target:
                scan_target.status = "completed"
                scan_target.pages_scanned = len(self.visited_urls)
                scan_target.vulnerabilities_found = self.vulnerability_count
                scan_target.scan_duration = scan_duration
                self.db_session.commit()
        
        # Clean up browser
        if self.browser:
            self.browser.quit()
            
        self.active = False
            
        # Return scan summary
        return {
            "scan_id": self.scan_id,
            "target_url": self.base_url,
            "scan_duration": format_scan_duration(scan_duration),
            "pages_scanned": len(self.visited_urls),
            "vulnerabilities_found": self.vulnerability_count,
            "vulnerabilities": self.results
        }
        
    def _crawl_site(self):
        """Crawl the website and scan for vulnerabilities"""
        while not self.url_queue.empty() and self.active:
            current_url, depth = self.url_queue.get()
            
            # Skip if already visited or max depth reached
            if current_url in self.visited_urls or depth > self.scan_depth:
                continue
                
            # Skip if not in same domain and subdomains are not included
            if not self.include_subdomains and not is_same_domain(current_url, self.base_url):
                continue
                
            # Mark as visited
            self.visited_urls.add(current_url)
            
            # Stop if reached max URLs
            if len(self.visited_urls) >= self.config["max_urls_to_scan"]:
                logger.info(f"Reached maximum number of URLs to scan ({self.config['max_urls_to_scan']})")
                break
                
            # Get page content
            try:
                # Try with requests first
                response = requests.get(
                    current_url, 
                    timeout=self.config["request_timeout"],
                    headers={"User-Agent": "Mozilla/5.0 SecurityScanner/1.0"}
                )
                
                # Record page in database
                if self.db_session and self.scan_id:
                    from .database import ScannedPage
                    page = ScannedPage(
                        scan_target_id=self.scan_id,
                        url=current_url,
                        status_code=response.status_code,
                        content_type=response.headers.get("Content-Type", ""),
                        response_time=response.elapsed.total_seconds() * 1000,
                        page_size=len(response.content),
                        scan_status="in_progress"
                    )
                    self.db_session.add(page)
                    self.db_session.commit()
                    page_id = page.id
                else:
                    page_id = None
                
                # Only proceed if page is HTML
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" in content_type and response.status_code == 200:
                    html_content = response.text
                    
                    # Extract information
                    links = extract_links(html_content, current_url)
                    forms = extract_forms(html_content)
                    has_login_form = detect_login_form(forms)
                    technologies = detect_technology(html_content, response.headers)
                    
                    # Update page info in database
                    if self.db_session and page_id:
                        page = self.db_session.query(ScannedPage).get(page_id)
                        if page:
                            page.has_forms = len(forms) > 0
                            page.has_login_form = has_login_form
                            page.has_javascript = "javascript" in html_content.lower()
                            self.db_session.commit()
                    
                    # Perform security checks
                    self._perform_security_checks(current_url, html_content, forms, page_id)
                    
                    # Queue new links for next depth
                    for link in links:
                        if link not in self.visited_urls:
                            self.url_queue.put((link, depth + 1))
                
                # Update page status
                if self.db_session and page_id:
                    page = self.db_session.query(ScannedPage).get(page_id)
                    if page:
                        page.scan_status = "completed"
                        self.db_session.commit()
                
            except Exception as e:
                logger.error(f"Error scanning {current_url}: {str(e)}")
                
                # Record error in database
                if self.db_session and self.scan_id and hasattr(self, 'page_id') and self.page_id:
                    from .database import ScannedPage
                    page = self.db_session.query(ScannedPage).get(self.page_id)
                    if page:
                        page.scan_status = "failed"
                        self.db_session.commit()
    
    def _perform_security_checks(self, url, html_content, forms, page_id=None):
        """Run security checks on the page"""
        # Run checks based on configuration
        if self.config.get("check_sql_injection"):
            self._check_sql_injection(url, forms, page_id)
            
        if self.config.get("check_xss"):
            self._check_xss(url, html_content, forms, page_id)
            
        if self.config.get("check_csrf") and forms:
            self._check_csrf(url, forms, page_id)
            
        if self.config.get("check_xxe"):
            self._check_xxe(url, page_id)
            
        if self.config.get("check_auth") and detect_login_form(forms):
            self._check_auth_vulnerabilities(url, forms, page_id)

    def _add_vulnerability(self, url, vuln_type, severity, description, evidence, remediation, page_id=None):
        """Add a vulnerability to results and database"""
        risk_score = calculate_risk_score(vuln_type, severity)
        
        vuln = {
            "url": url,
            "type": vuln_type,
            "severity": severity,
            "risk_score": risk_score,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "discovered_at": datetime.now().isoformat()
        }
        
        self.results.append(vuln)
        self.vulnerability_count += 1
        
        # Add to database if session available
        if self.db_session and self.scan_id:
            from .database import Vulnerability
            db_vuln = Vulnerability(
                scan_target_id=self.scan_id,
                page_id=page_id,
                vulnerability_type=vuln_type,
                severity=severity,
                risk_score=risk_score,
                description=description,
                evidence=evidence,
                remediation=remediation
            )
            self.db_session.add(db_vuln)
            self.db_session.commit()
    
    def _check_sql_injection(self, url, forms, page_id=None):
        """Check for SQL injection vulnerabilities in forms"""
        if not forms:
            return
            
        payloads = generate_payload_for_vulnerability("sql_injection")
        
        for form in forms:
            # Try each input
            for input_field in form.get("inputs", []):
                input_name = input_field.get("name", "")
                
                # Skip file inputs and submit buttons
                if input_field.get("type") in ["file", "submit", "button", "image", "reset"]:
                    continue
                    
                # Test each payload
                for payload in payloads:
                    # Simple detection based on error messages
                    form_data = {inp["name"]: "" for inp in form.get("inputs", []) if inp.get("name")}
                    form_data[input_name] = payload
                    
                    try:
                        action_url = urljoin(url, form.get("action", ""))
                        method = form.get("method", "get").lower()
                        
                        if method == "get":
                            response = requests.get(action_url, params=form_data, timeout=self.config["request_timeout"])
                        else:
                            response = requests.post(action_url, data=form_data, timeout=self.config["request_timeout"])
                        
                        # Check for SQL error messages
                        error_signatures = [
                            "SQL syntax", "mysql_fetch_array", "ORA-", "Oracle Error",
                            "Microsoft SQL", "ODBC Driver", "syntax error", "unclosed quotation mark",
                            "You have an error in your SQL syntax", "mysql_fetch", "pg_fetch",
                            "invalid query", "SQL command not properly ended"
                        ]
                        
                        if any(sig.lower() in response.text.lower() for sig in error_signatures):
                            self._add_vulnerability(
                                url=url,
                                vuln_type="SQL Injection",
                                severity="High",
                                description=f"Possible SQL injection vulnerability detected in form field '{input_name}'",
                                evidence=f"Payload: {payload}\nResponse contained SQL error messages",
                                remediation="Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
                                page_id=page_id
                            )
                            return  # Stop after finding one vulnerability per form
                    
                    except Exception as e:
                        logger.error(f"Error testing SQL injection on {url}: {str(e)}")

    def _check_xss(self, url, html_content, forms, page_id=None):
        """Check for Cross-Site Scripting vulnerabilities"""
        payloads = generate_payload_for_vulnerability("xss")
        
        # Check for reflected XSS via URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            # Try to inject XSS payloads into URL parameters
            query_params = parsed_url.query.split("&")
            for param in query_params:
                if "=" in param:
                    param_name = param.split("=")[0]
                    
                    for payload in payloads:
                        test_url = url.replace(param, f"{param_name}={payload}")
                        
                        try:
                            response = requests.get(test_url, timeout=self.config["request_timeout"])
                            
                            # Check if payload is reflected in the response
                            if payload in response.text:
                                self._add_vulnerability(
                                    url=url,
                                    vuln_type="Reflected XSS",
                                    severity="High",
                                    description=f"Reflected XSS vulnerability detected in URL parameter '{param_name}'",
                                    evidence=f"Payload: {payload}\nPayload was reflected in the response",
                                    remediation="Sanitize and validate all user inputs. Use content security policy and output encoding.",
                                    page_id=page_id
                                )
                                return  # Stop after finding one vulnerability per URL
                        
                        except Exception as e:
                            logger.error(f"Error testing XSS on {url}: {str(e)}")
        
        # Check forms for XSS
        for form in forms:
            # Try each input
            for input_field in form.get("inputs", []):
                input_name = input_field.get("name", "")
                
                # Skip file inputs and submit buttons
                if input_field.get("type") in ["file", "submit", "button", "image", "reset"]:
                    continue
                    
                # Test each payload
                for payload in payloads:
                    form_data = {inp["name"]: "" for inp in form.get("inputs", []) if inp.get("name")}
                    form_data[input_name] = payload
                    
                    try:
                        action_url = urljoin(url, form.get("action", ""))
                        method = form.get("method", "get").lower()
                        
                        if method == "get":
                            response = requests.get(action_url, params=form_data, timeout=self.config["request_timeout"])
                        else:
                            response = requests.post(action_url, data=form_data, timeout=self.config["request_timeout"])
                        
                        # Check if payload is reflected in the response
                        if payload in response.text:
                            self._add_vulnerability(
                                url=url,
                                vuln_type="Reflected XSS",
                                severity="High",
                                description=f"Reflected XSS vulnerability detected in form field '{input_name}'",
                                evidence=f"Payload: {payload}\nPayload was reflected in the response",
                                remediation="Sanitize and validate all user inputs. Use content security policy and output encoding.",
                                page_id=page_id
                            )
                            return  # Stop after finding one vulnerability per form
                    
                    except Exception as e:
                        logger.error(f"Error testing XSS on {url}: {str(e)}")

    def _check_csrf(self, url, forms, page_id=None):
        """Check for Cross-Site Request Forgery vulnerabilities"""
        for form in forms:
            # Skip forms with GET method (not vulnerable to CSRF)
            if form.get("method", "get").lower() == "get":
                continue
                
            # Look for CSRF token in form inputs
            has_csrf_token = False
            for input_field in form.get("inputs", []):
                input_name = input_field.get("name", "").lower()
                if any(token_name in input_name for token_name in ["csrf", "token", "nonce", "xsrf"]):
                    has_csrf_token = True
                    break
            
            # Check if form doesn't have CSRF protection
            if not has_csrf_token:
                self._add_vulnerability(
                    url=url,
                    vuln_type="CSRF",
                    severity="Medium",
                    description="Form lacks CSRF protection tokens",
                    evidence=f"Form action: {form.get('action', '')}\nMethod: {form.get('method', 'get')}",
                    remediation="Implement anti-CSRF tokens in all forms that modify state. Consider using SameSite cookies.",
                    page_id=page_id
                )

    def _check_xxe(self, url, page_id=None):
        """Check for XML External Entity vulnerabilities"""
        # This is a simplified check for XXE, real tests require more complex payloads
        # and specific endpoints that accept XML data
        
        xxe_payloads = generate_payload_for_vulnerability("xxe")
        
        # Look for potential XML endpoints
        xml_endpoints = [
            f"{url}/api/",
            f"{url}/soap/",
            f"{url}/xml/",
            f"{url}/rss/",
            f"{url}/services/"
        ]
        
        headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml",
            "User-Agent": "Mozilla/5.0 SecurityScanner/1.0"
        }
        
        for endpoint in xml_endpoints:
            for payload in xxe_payloads:
                try:
                    response = requests.post(
                        endpoint, 
                        data=payload, 
                        headers=headers, 
                        timeout=self.config["request_timeout"]
                    )
                    
                    # Look for potential signs of XXE vulnerability
                    if response.status_code == 200 and any(
                        sign in response.text for sign in [
                            "root:x:", "/etc/passwd", "uid=", "xmlns:xi=", 
                            "boot", "nobody:", "mysql:", "www-data:"
                        ]
                    ):
                        self._add_vulnerability(
                            url=url,
                            vuln_type="XXE",
                            severity="High",
                            description="Potential XML External Entity (XXE) vulnerability detected",
                            evidence=f"Endpoint: {endpoint}\nPayload: {payload}\nResponse suggests XXE processing",
                            remediation="Disable XML external entity processing in the XML parser. Use secure XML parsing libraries.",
                            page_id=page_id
                        )
                        return  # Stop after finding one vulnerability
                        
                except Exception as e:
                    logger.debug(f"Error testing XXE on {endpoint}: {str(e)}")

    def _check_auth_vulnerabilities(self, url, forms, page_id=None):
        """Check for authentication vulnerabilities"""
        # Look for login forms without HTTPS
        for form in forms:
            if detect_login_form([form]) and url.startswith("http://"):
                self._add_vulnerability(
                    url=url,
                    vuln_type="Insecure Authentication",
                    severity="High",
                    description="Login form submitted over insecure HTTP connection",
                    evidence=f"Form action: {form.get('action', '')}\nURL: {url}",
                    remediation="Ensure all authentication forms use HTTPS. Implement HSTS policy.",
                    page_id=page_id
                )
                break
        
        # Check for missing security headers
        try:
            response = requests.get(url, timeout=self.config["request_timeout"])
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                "Strict-Transport-Security": "Missing HSTS header",
                "Content-Security-Policy": "Missing Content-Security-Policy header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-Frame-Options": "Missing X-Frame-Options header",
                "X-XSS-Protection": "Missing X-XSS-Protection header"
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in headers:
                    missing_headers.append(message)
            
            if missing_headers:
                self._add_vulnerability(
                    url=url,
                    vuln_type="Missing Security Headers",
                    severity="Medium",
                    description="Missing important security headers that help protect against common attacks",
                    evidence="\n".join(missing_headers),
                    remediation="Implement the missing security headers in your web server or application.",
                    page_id=page_id
                )
        
        except Exception as e:
            logger.error(f"Error checking security headers on {url}: {str(e)}")

    def stop_scan(self):
        """Stop an ongoing scan"""
        self.active = False
        logger.info("Stopping scan...")
        
    def get_scan_status(self):
        """Get current scan status"""
        if not self.active:
            return "idle"
            
        return {
            "active": True,
            "base_url": self.base_url,
            "pages_scanned": len(self.visited_urls),
            "vulnerabilities_found": self.vulnerability_count,
            "elapsed_time": format_scan_duration(time.time() - self.start_time)
        }
import os
import re
import json
import logging
import smtplib
import requests
import urllib.parse
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Load environment variables
load_dotenv()

# Configure logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/websec_scanner.log")

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("websec-scanner")

# Email configuration
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
NOTIFICATION_EMAIL = os.getenv("NOTIFICATION_EMAIL")

# Encryption setup
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
cipher_suite = None
if ENCRYPTION_KEY:
    # Generate a Fernet key from the provided encryption key
    import base64
    import hashlib
    key = base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY.encode()).digest())
    cipher_suite = Fernet(key)


def normalize_url(url):
    """Normalize a URL by adding protocol if missing and handling trailing slashes"""
    if not url:
        return None
        
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}{parsed.params}{parsed.query}{parsed.fragment}"


def is_valid_url(url):
    """Check if a URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def get_domain_from_url(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc


def is_same_domain(url1, url2):
    """Check if two URLs belong to the same domain"""
    return get_domain_from_url(url1) == get_domain_from_url(url2)


def extract_links(html_content, base_url):
    """Extract all links from HTML content"""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []
    
    for a_tag in soup.find_all('a', href=True):
        href = a_tag.get('href')
        if href and not href.startswith('#') and not href.startswith('javascript:'):
            links.append(urljoin(base_url, href))
            
    return links


def extract_forms(html_content):
    """Extract all forms from HTML content"""
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        
        for input_field in form.find_all(['input', 'textarea', 'select']):
            input_type = input_field.get('type', 'text')
            input_name = input_field.get('name', '')
            input_value = input_field.get('value', '')
            
            if input_name:
                form_data['inputs'].append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })
                
        forms.append(form_data)
        
    return forms


def detect_login_form(forms):
    """Detect if any of the forms is a login form"""
    login_keywords = ['login', 'log-in', 'log_in', 'signin', 'sign-in', 'sign_in', 'auth', 'authenticate']
    password_fields = ['password', 'passwd', 'pass', 'pwd']
    
    for form in forms:
        # Check if form action contains login keywords
        action = form.get('action', '').lower()
        if any(keyword in action for keyword in login_keywords):
            return True
            
        # Check if form has password field
        inputs = form.get('inputs', [])
        input_names = [inp.get('name', '').lower() for inp in inputs]
        input_types = [inp.get('type', '').lower() for inp in inputs]
        
        if 'password' in input_types or any(pwd in input_names for pwd in password_fields):
            return True
            
    return False


def calculate_risk_score(vulnerability_type, severity):
    """Calculate a risk score based on vulnerability type and severity"""
    # Base scores by severity
    severity_scores = {
        'critical': 9.0,
        'high': 7.0,
        'medium': 5.0,
        'low': 3.0,
        'info': 1.0
    }
    
    # Vulnerability type modifiers
    vuln_modifiers = {
        'sql_injection': 1.0,
        'xss': 0.8,
        'csrf': 0.7,
        'ssrf': 0.9,
        'xxe': 0.9,
        'broken_auth': 0.9,
        'sensitive_data_exposure': 0.8,
        'security_misconfiguration': 0.6,
        'insecure_deserialization': 0.8,
        'using_components_with_vulnerabilities': 0.7,
        'insufficient_logging_monitoring': 0.5
    }
    
    base_score = severity_scores.get(severity.lower(), 5.0)
    modifier = vuln_modifiers.get(vulnerability_type.lower().replace(' ', '_'), 0.7)
    
    final_score = base_score * modifier
    
    # Cap at 10.0
    return min(final_score, 10.0)


def send_email_notification(subject, body, attachment_path=None):
    """Send email notification with optional attachment"""
    if not all([SMTP_SERVER, SMTP_USER, SMTP_PASSWORD, NOTIFICATION_EMAIL]):
        logger.warning("Email notification settings are missing. Skipping email notification.")
        return False
        
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = NOTIFICATION_EMAIL
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        # Attach file if provided
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, 'rb') as file:
                attachment = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
                attachment['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                msg.attach(attachment)
        
        # Connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
            
        logger.info(f"Email notification sent to {NOTIFICATION_EMAIL}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email notification: {str(e)}")
        return False


def encrypt_sensitive_data(data):
    """Encrypt sensitive data using Fernet symmetric encryption"""
    if not cipher_suite:
        logger.warning("Encryption key not configured. Data will not be encrypted.")
        return data
        
    try:
        if isinstance(data, str):
            return cipher_suite.encrypt(data.encode()).decode()
        elif isinstance(data, bytes):
            return cipher_suite.encrypt(data).decode()
        else:
            return data
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        return data


def decrypt_sensitive_data(encrypted_data):
    """Decrypt sensitive data encrypted with Fernet"""
    if not cipher_suite or not encrypted_data:
        return encrypted_data
        
    try:
        if isinstance(encrypted_data, str):
            return cipher_suite.decrypt(encrypted_data.encode()).decode()
        elif isinstance(encrypted_data, bytes):
            return cipher_suite.decrypt(encrypted_data).decode()
        else:
            return encrypted_data
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return encrypted_data


def generate_payload_for_vulnerability(vuln_type):
    """Generate test payloads for different vulnerability types"""
    payloads = {
        'sql_injection': [
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM users --",
            "1' OR '1'='1",
            "admin'--",
            "1'; SELECT * FROM information_schema.tables; --"
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror='alert(\"XSS\")'>",
            "<svg onload='alert(\"XSS\")'>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(`XSS`)'>",
            "'\"><script>alert(1)</script>"
        ],
        'csrf': [
            # CSRF test typically requires custom HTML forms
            "<form action='https://vulnerable-site.com/transfer' method='POST'>"
            "<input type='hidden' name='recipient' value='attacker'>"
            "<input type='hidden' name='amount' value='1000'>"
            "</form>"
        ],
        'xxe': [
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
            "<?xml version='1.0'?><!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/hostname'>]><data>&file;</data>"
        ],
        'ssrf': [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "https://webhook.site/unique-id",
            "file:///etc/passwd"
        ]
    }
    
    return payloads.get(vuln_type.lower().replace(' ', '_'), [])


def detect_technology(html_content, headers):
    """Detect technologies used by the website"""
    technologies = []
    
    # Check headers for technology clues
    server = headers.get('Server', '')
    if server:
        technologies.append(f"Server: {server}")
        
    powered_by = headers.get('X-Powered-By', '')
    if powered_by:
        technologies.append(f"Powered by: {powered_by}")
    
    # Check for common JS libraries
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Check for JavaScript libraries
    script_patterns = {
        'jQuery': r'jquery[.-](\d+\.\d+\.\d+)',
        'React': r'react[.-](\d+\.\d+\.\d+)',
        'Vue.js': r'vue[.-](\d+\.\d+\.\d+)',
        'Angular': r'angular[.-](\d+\.\d+\.\d+)',
        'Bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
    }
    
    scripts = [script.get('src', '') for script in soup.find_all('script', src=True)]
    for script in scripts:
        for tech, pattern in script_patterns.items():
            match = re.search(pattern, script, re.IGNORECASE)
            if match:
                technologies.append(f"{tech} {match.group(1)}")
    
    # Check for meta generator tag
    meta_generator = soup.find('meta', attrs={'name': 'generator'})
    if meta_generator and meta_generator.get('content'):
        technologies.append(f"Generator: {meta_generator.get('content')}")
    
    return technologies


def format_scan_duration(seconds):
    """Format scan duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours" 
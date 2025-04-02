# CYBERSEC SCAN | Web Application Security Scanner

![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

A powerful, modern web application security scanner capable of detecting vulnerabilities according to the OWASP Top 10. Built with a cyberpunk aesthetic and powerful scanning capabilities.

## 🔐 Features

- **URL Scanning**: Analyze any website for security vulnerabilities
- **OWASP Top 10 Detection**: SQL Injection, XSS, CSRF, SSRF, Broken Authentication
- **Automated Crawling**: Discover and scan all pages of the target application
- **Modern Dashboard**: Visualize threats with a Streamlit-powered dashboard
- **Comprehensive Reports**: Generate detailed vulnerability reports
- **Multi-platform**: CLI and API access for flexibility and integration

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cybersec-scan.git
cd cybersec-scan

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env with your configuration
```

## 🛠️ Usage

### Web Interface

```bash
cd frontend
streamlit run app.py
```

### CLI Usage

```bash
python cli/scanner_cli.py --url https://example.com --depth 2
```

### API Server

```bash
cd backend
uvicorn main:app --reload
```

## 📊 Dashboard

The Streamlit dashboard is available at `http://localhost:8501` after starting the frontend application, providing:

- Real-time vulnerability visualization
- Historical scan data
- Remediation suggestions
- Exportable PDF reports

## 🔒 Security Scanning Capabilities

- SQL Injection Detection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- Broken Authentication
- Sensitive Data Exposure
- XML External Entities (XXE)
- Security Misconfigurations

## 🛡️ Disclaimer

This tool is intended for security professionals and developers to test their own applications. Never use this tool against applications without explicit permission.

## 📜 License

MIT License - see LICENSE for details.

## Author

Developed by Jeremy Martinez-Quinones.
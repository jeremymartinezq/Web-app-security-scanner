import os
import json
import time
import datetime
from jinja2 import Environment, FileSystemLoader
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Report configuration
REPORT_PATH = os.getenv("REPORT_PATH", "reports/")
REPORT_TEMPLATE = os.getenv("REPORT_TEMPLATE", "default")

# Ensure reports directory exists
os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

# Templates path
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# Create Jinja2 environment
env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=True
)

class ReportGenerator:
    """Generate security scan reports in various formats"""
    
    def __init__(self, scan_data, template="default"):
        """Initialize with scan data"""
        self.scan_data = scan_data
        self.template = template
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = REPORT_PATH
        
        # Create default template if it doesn't exist
        self._ensure_default_template_exists()
    
    def _ensure_default_template_exists(self):
        """Create default HTML template if it doesn't exist"""
        default_template_path = os.path.join(TEMPLATES_DIR, "default.html")
        
        if not os.path.exists(default_template_path):
            with open(default_template_path, 'w') as f:
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {{ scan.url }}</title>
    <style>
        :root {
            --primary-color: #00ffff;
            --secondary-color: #ff00ff;
            --bg-color: #0a0a16;
            --text-color: #e0e0e0;
            --heading-color: #00ffff;
            --card-bg: #151525;
            --danger-color: #ff3e3e;
            --warning-color: #ffcc00;
            --success-color: #00ff66;
            --info-color: #0099ff;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            text-align: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--primary-color);
            padding-bottom: 1rem;
            position: relative;
        }
        
        header::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 10%;
            width: 80%;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--secondary-color), transparent);
        }
        
        h1, h2, h3, h4 {
            color: var(--heading-color);
            font-weight: 600;
        }
        
        h1 {
            font-size: 2.4rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .subtitle {
            color: var(--secondary-color);
            font-size: 1.2rem;
            margin-bottom: 1rem;
        }
        
        .summary-card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(0, 255, 255, 0.1);
            border: 1px solid rgba(0, 255, 255, 0.2);
        }
        
        .summary-stats {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .stat-box {
            flex: 1;
            min-width: 200px;
            background: rgba(21, 21, 37, 0.7);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid var(--primary-color);
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
            color: var(--primary-color);
        }
        
        .stat-label {
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 2rem;
            overflow: hidden;
            border-radius: 8px;
        }
        
        .vulnerability-table th {
            background-color: rgba(0, 255, 255, 0.2);
            color: var(--primary-color);
            text-align: left;
            padding: 1rem;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .vulnerability-table td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .vulnerability-table tr:nth-child(even) {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        .vulnerability-table tr:hover {
            background-color: rgba(0, 255, 255, 0.1);
        }
        
        .severity {
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background-color: var(--danger-color);
            color: #000;
        }
        
        .severity-high {
            background-color: #ff5722;
            color: #000;
        }
        
        .severity-medium {
            background-color: var(--warning-color);
            color: #000;
        }
        
        .severity-low {
            background-color: var(--success-color);
            color: #000;
        }
        
        .severity-info {
            background-color: var(--info-color);
            color: #000;
        }
        
        .vuln-details {
            margin: 2rem 0;
            padding: 1.5rem;
            background: var(--card-bg);
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 255, 0.2);
        }
        
        .detail-item {
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px dashed rgba(255, 255, 255, 0.1);
        }
        
        .detail-item:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        
        .detail-label {
            font-weight: bold;
            color: var(--primary-color);
            margin-bottom: 0.25rem;
            display: block;
        }
        
        .evidence-box {
            background: rgba(0, 0, 0, 0.3);
            padding: 1rem;
            border-radius: 4px;
            font-family: monospace;
            overflow-x: auto;
            white-space: pre-wrap;
            margin-top: 0.5rem;
        }
        
        .remediation-box {
            background: rgba(0, 255, 102, 0.1);
            border-left: 4px solid var(--success-color);
            padding: 1rem;
            margin-top: 0.5rem;
        }
        
        footer {
            margin-top: 3rem;
            text-align: center;
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.6);
            padding: 1rem 0;
            border-top: 1px solid rgba(0, 255, 255, 0.2);
        }
        
        .timestamp {
            margin-top: 0.5rem;
        }
        
        .glow-text {
            text-shadow: 0 0 10px var(--primary-color), 0 0 20px var(--primary-color);
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .summary-stats {
                flex-direction: column;
            }
            
            .stat-box {
                width: 100%;
            }
            
            .vulnerability-table th, .vulnerability-table td {
                padding: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span class="glow-text">CyberSec</span> Scan Report</h1>
            <div class="subtitle">Web Application Security Analysis</div>
        </header>
        
        <section class="summary-card">
            <h2>Scan Summary</h2>
            <div class="summary-stats">
                <div class="stat-box">
                    <div class="stat-value">{{ scan.target_url }}</div>
                    <div class="stat-label">Target URL</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{{ scan.pages_scanned }}</div>
                    <div class="stat-label">Pages Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{{ scan.vulnerabilities_found }}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{{ scan.scan_duration }}</div>
                    <div class="stat-label">Scan Duration</div>
                </div>
            </div>
        </section>
        
        {% if scan.vulnerabilities %}
        <section>
            <h2>Vulnerability Summary</h2>
            
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>URL</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in scan.vulnerabilities %}
                    <tr>
                        <td>{{ vuln.type }}</td>
                        <td>
                            <span class="severity severity-{{ vuln.severity|lower }}">
                                {{ vuln.severity }}
                            </span>
                        </td>
                        <td>{{ vuln.url }}</td>
                        <td>{{ vuln.risk_score|round(1) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>Detailed Findings</h2>
            
            {% for vuln in scan.vulnerabilities %}
            <div class="vuln-details">
                <h3>{{ vuln.type }} <span class="severity severity-{{ vuln.severity|lower }}">{{ vuln.severity }}</span></h3>
                
                <div class="detail-item">
                    <span class="detail-label">Affected URL</span>
                    {{ vuln.url }}
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Description</span>
                    {{ vuln.description }}
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Evidence</span>
                    <div class="evidence-box">{{ vuln.evidence }}</div>
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Remediation</span>
                    <div class="remediation-box">{{ vuln.remediation }}</div>
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Risk Score</span>
                    {{ vuln.risk_score|round(1) }}/10.0
                </div>
                
                <div class="detail-item">
                    <span class="detail-label">Discovered At</span>
                    {{ vuln.discovered_at }}
                </div>
            </div>
            {% endfor %}
        </section>
        {% else %}
        <section class="summary-card">
            <h2>No Vulnerabilities Found</h2>
            <p>The scan did not detect any vulnerabilities in the target website. However, this does not guarantee that the site is completely secure. Continuous security testing is recommended.</p>
        </section>
        {% endif %}
        
        <footer>
            <p>Generated by CyberSec Scan - Web Application Security Scanner</p>
            <p class="timestamp">Report generated on: {{ timestamp }}</p>
        </footer>
    </div>
</body>
</html>""")
    
    def generate_html_report(self):
        """Generate HTML report from scan data"""
        template_name = f"{self.template}.html"
        template = env.get_template(template_name)
        
        # Prepare data for template
        context = {
            "scan": self.scan_data,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Render HTML
        html_content = template.render(**context)
        
        # Generate filename
        target_domain = self.scan_data.get('target_url', 'unknown').replace('://', '_').replace('/', '_')
        filename = f"security_report_{target_domain}_{self.timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        # Save report
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return filepath
        
    def generate_pdf_report(self):
        """Generate PDF report from HTML report"""
        try:
            import weasyprint
            
            # First generate HTML report
            html_path = self.generate_html_report()
            
            # Convert to PDF
            pdf_path = html_path.replace('.html', '.pdf')
            
            # Generate PDF
            weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
            
            return pdf_path
        except ImportError:
            # WeasyPrint not installed
            return None
    
    def generate_graphs(self):
        """Generate graphs for vulnerabilities by severity and type"""
        if not self.scan_data.get('vulnerabilities'):
            return None
            
        # Create directory for graphs
        graphs_dir = os.path.join(self.output_dir, 'graphs')
        os.makedirs(graphs_dir, exist_ok=True)
        
        # Extract vulnerability data
        vulnerabilities = self.scan_data.get('vulnerabilities', [])
        df = pd.DataFrame(vulnerabilities)
        
        # Graph 1: Vulnerabilities by severity
        severity_counts = df['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        # Sort by severity level
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        severity_counts['Severity'] = pd.Categorical(
            severity_counts['Severity'], 
            categories=severity_order, 
            ordered=True
        )
        severity_counts = severity_counts.sort_values('Severity')
        
        # Define colors for severity levels
        severity_colors = {
            'Critical': '#ff3e3e',
            'High': '#ff5722',
            'Medium': '#ffcc00',
            'Low': '#00ff66',
            'Info': '#0099ff'
        }
        
        # Create bar chart
        fig_severity = px.bar(
            severity_counts, 
            x='Severity', 
            y='Count',
            color='Severity',
            color_discrete_map=severity_colors,
            title='Vulnerabilities by Severity',
            template='plotly_dark'
        )
        
        fig_severity.update_layout(
            paper_bgcolor='#0a0a16',
            plot_bgcolor='#151525',
            font=dict(color='#e0e0e0'),
            title_font=dict(color='#00ffff', size=20),
            xaxis=dict(title_font=dict(color='#00ffff')),
            yaxis=dict(title_font=dict(color='#00ffff'))
        )
        
        # Save graph
        severity_graph_path = os.path.join(graphs_dir, f'severity_graph_{self.timestamp}.html')
        fig_severity.write_html(severity_graph_path)
        
        # Graph 2: Vulnerabilities by type
        type_counts = df['type'].value_counts().reset_index()
        type_counts.columns = ['Type', 'Count']
        
        # Create bar chart
        fig_type = px.bar(
            type_counts, 
            x='Type', 
            y='Count',
            color='Count',
            color_continuous_scale=['#00ffff', '#ff00ff'],
            title='Vulnerabilities by Type',
            template='plotly_dark'
        )
        
        fig_type.update_layout(
            paper_bgcolor='#0a0a16',
            plot_bgcolor='#151525',
            font=dict(color='#e0e0e0'),
            title_font=dict(color='#00ffff', size=20),
            xaxis=dict(title_font=dict(color='#00ffff')),
            yaxis=dict(title_font=dict(color='#00ffff'))
        )
        
        # Save graph
        type_graph_path = os.path.join(graphs_dir, f'type_graph_{self.timestamp}.html')
        fig_type.write_html(type_graph_path)
        
        return {
            'severity_graph': severity_graph_path,
            'type_graph': type_graph_path
        }
    
    def generate_json_report(self):
        """Generate JSON report"""
        # Generate filename
        target_domain = self.scan_data.get('target_url', 'unknown').replace('://', '_').replace('/', '_')
        filename = f"security_report_{target_domain}_{self.timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # Save report
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.scan_data, f, indent=2)
            
        return filepath
    
    def generate_all_reports(self):
        """Generate all available report formats"""
        reports = {}
        
        # Generate HTML report
        html_path = self.generate_html_report()
        reports['html'] = html_path
        
        # Generate JSON report
        json_path = self.generate_json_report()
        reports['json'] = json_path
        
        # Generate graphs
        graphs = self.generate_graphs()
        if graphs:
            reports['graphs'] = graphs
        
        # Try to generate PDF if WeasyPrint is available
        try:
            pdf_path = self.generate_pdf_report()
            if pdf_path:
                reports['pdf'] = pdf_path
        except Exception as e:
            print(f"Error generating PDF report: {str(e)}")
        
        return reports 
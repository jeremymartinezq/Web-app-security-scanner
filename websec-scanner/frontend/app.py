import os
import sys
import time
import json
import requests
import pandas as pd
import plotly.express as px
import streamlit as st
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import utility functions
from backend.utils import normalize_url, is_valid_url

# Configure Streamlit page
st.set_page_config(
    page_title="CyberSec Scan",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API endpoint configuration
API_URL = os.getenv("API_URL", "http://localhost:8000")

# Apply custom CSS for cyberpunk theme
def apply_custom_css():
    st.markdown("""
    <style>
    /* CRITICAL SIDEBAR BACKGROUND OVERRIDE - DO NOT REMOVE */
    [data-testid="stSidebar"] {
        background-color: #0a0a16 !important;
    }
    [data-testid="stSidebar"] > div {
        background-color: #0a0a16 !important;
    }
    [data-testid="stSidebar"] div {
        background-color: #0a0a16 !important;
    }
    [data-testid="stSidebar"] section {
        background-color: #0a0a16 !important;
    }
    [data-testid="stSidebar"] .stMarkdown {
        background-color: #0a0a16 !important;
    }
    div[data-testid="stSidebarUserContent"] {
        background-color: #0a0a16 !important;
    }
    
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
    
    .stApp {
        background-color: var(--bg-color);
        color: var(--text-color);
    }
    
    h1, h2, h3 {
        color: var(--heading-color) !important;
    }
    
    h1 {
        text-shadow: 0 0 10px var(--primary-color), 0 0 20px var(--primary-color);
        font-weight: bold;
        text-transform: uppercase;
    }
    
    .css-1cpxqw2, .css-r421ms {
        border: 1px solid var(--primary-color);
        border-radius: 10px;
        background-color: var(--card-bg);
        padding: 20px;
        margin-bottom: 15px;
    }
    
    .stButton button {
        background-color: var(--primary-color);
        color: black;
        border: none;
        padding: 10px 20px;
        font-weight: bold;
        border-radius: 5px;
        transition: all 0.3s;
    }
    
    .stButton button:hover {
        background-color: var(--secondary-color);
        box-shadow: 0 0 15px var(--secondary-color);
        transform: translateY(-2px);
    }
    
    .stTextInput input, .stNumberInput input, .stSelectbox, .stMultiselect {
        background-color: #1e1e30;
        color: white;
        border: 1px solid var(--primary-color);
        border-radius: 5px;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: #1e1e30;
        border-radius: 4px 4px 0 0;
        padding: 10px 16px;
        border: 1px solid var(--primary-color);
        border-bottom: none;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #151525;
        border-color: var(--secondary-color);
        color: var(--secondary-color);
        box-shadow: 0 0 10px var(--secondary-color);
    }
    
    /* Sidebar title and text style */
    div[data-testid="stSidebar"] h1 {
        color: var(--primary-color) !important;
        text-shadow: 0 0 5px var(--primary-color);
        margin-bottom: 20px;
    }
    
    /* Styled radio buttons in sidebar */
    div[data-testid="stSidebar"] .stRadio > div > div > label {
        background-color: #0a0a16 !important;
        padding: 10px;
        border-radius: 8px;
        border: 2px solid rgba(0, 255, 255, 0.5);
        margin-bottom: 10px;
        cursor: pointer;
        display: block;
        transition: all 0.3s ease;
    }
    
    div[data-testid="stSidebar"] .stRadio > div > div > label:hover {
        border-color: var(--primary-color);
        box-shadow: 0 0 15px var(--primary-color);
        transform: translateY(-2px);
    }
    
    /* Make radio labels more visible & attractive */
    div[data-testid="stSidebar"] .stRadio label {
        color: white !important;
        font-size: 18px !important;
        font-weight: 700 !important;
        text-shadow: 0 0 5px rgba(0, 255, 255, 0.5);
    }
    
    /* Navigation item styling */
    div[data-testid="stSidebar"] .stRadio input:checked + div {
        background-color: #151525 !important;
        border: 2px solid var(--secondary-color) !important;
        box-shadow: 0 0 10px var(--secondary-color) !important;
    }
    
    /* Fix general text visibility */
    div[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        color: white !important;
    }
    
    div[data-testid="stSidebar"] .scanners-wrapper .scanner-card {
        margin-bottom: 8px;
        background-color: rgba(10, 10, 22, 0.8);
    }
    
    /* Fix text visibility in main content */
    p, span, label, .stMarkdown {
        color: var(--text-color) !important;
        font-size: 16px;
    }
    
    /* Error message styling */
    div[data-testid="stAlert"] {
        background-color: rgba(255, 62, 62, 0.1);
        border: 1px solid var(--danger-color);
        border-radius: 8px;
        color: white !important;
    }
    
    div[data-testid="stAlert"] p {
        color: white !important;
    }
    
    /* Success message styling */
    div.element-container div[data-testid="stAlert"] {
        background-color: rgba(0, 255, 102, 0.1);
        border: 1px solid var(--success-color);
        border-radius: 8px;
    }
    
    .scan-summary {
        display: flex;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 10px;
    }
    
    .stat-card {
        background-color: var(--card-bg);
        border: 1px solid var(--primary-color);
        border-radius: 8px;
        padding: 20px;
        flex: 1;
        min-width: 200px;
        text-align: center;
    }
    
    .stat-value {
        font-size: 24px;
        font-weight: bold;
        color: var(--primary-color);
    }
    
    .stat-label {
        font-size: 14px;
        text-transform: uppercase;
        color: var(--text-color);
    }
    
    /* Custom colors for severity badges */
    .critical {
        color: var(--bg-color);
        background-color: var(--danger-color);
        padding: 5px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    
    .high {
        color: var(--bg-color);
        background-color: #ff5722;
        padding: 5px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    
    .medium {
        color: var(--bg-color);
        background-color: var(--warning-color);
        padding: 5px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    
    .low {
        color: var(--bg-color);
        background-color: var(--success-color);
        padding: 5px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    
    .info {
        color: var(--bg-color);
        background-color: var(--info-color);
        padding: 5px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    
    .stDataFrame {
        background-color: var(--card-bg);
        padding: 10px;
        border-radius: 8px;
        color: white !important;
    }
    
    /* Ensure dataframe text is visible */
    .stDataFrame td, .stDataFrame th {
        color: white !important;
    }
    
    .stProgress .st-bo {
        background-color: var(--primary-color);
    }
    
    .scanners-wrapper {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 10px;
        margin-top: 20px;
    }
    
    .scanner-card {
        background-color: var(--card-bg);
        border: 1px solid var(--primary-color);
        border-radius: 8px;
        padding: 15px;
        text-align: center;
        transition: all 0.3s;
        box-shadow: 0 0 5px rgba(0, 255, 255, 0.2);
    }
    
    .scanner-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 0 15px var(--primary-color);
        border-color: var(--primary-color);
    }
    
    .scanner-icon {
        font-size: 32px;
        margin-bottom: 10px;
        color: var(--primary-color);
        text-shadow: 0 0 8px var(--primary-color);
    }
    
    .scanner-active {
        border-color: var(--secondary-color);
        box-shadow: 0 0 10px var(--secondary-color);
        background-color: rgba(30, 30, 48, 0.9);
    }
    
    .scanner-disabled {
        opacity: 0.5;
        cursor: not-allowed;
        filter: grayscale(70%);
    }
    
    .footer {
        text-align: center;
        margin-top: 50px;
        padding: 20px;
        border-top: 1px solid var(--primary-color);
        color: var(--text-color);
        font-size: 12px;
    }
    </style>
    """, unsafe_allow_html=True)

def create_app_header():
    """Create application header"""
    st.markdown("""
    <div style="text-align: center; margin: 20px 0;">
        <h1>CYBERSEC SCAN</h1>
        <p style="color: #ff00ff; font-size: 18px; margin-top: -10px;">Web Application Security Scanner</p>
    </div>
    """, unsafe_allow_html=True)

def display_scan_form():
    """Display scan URL form"""
    with st.form(key="scan_form"):
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            url = st.text_input("Target URL", placeholder="https://example.com")
        
        with col2:
            scan_depth = st.number_input("Scan Depth", min_value=1, max_value=5, value=1)
        
        with col3:
            include_subdomains = st.checkbox("Include Subdomains")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Security Checks")
            col1a, col1b = st.columns(2)
            
            with col1a:
                check_sql = st.checkbox("SQL Injection", value=True)
                check_xss = st.checkbox("XSS", value=True)
                check_csrf = st.checkbox("CSRF", value=True)
            
            with col1b:
                check_ssrf = st.checkbox("SSRF", value=True)
                check_xxe = st.checkbox("XXE", value=True)
                check_auth = st.checkbox("Auth Vulns", value=True)
        
        with col2:
            st.markdown("### Advanced Options")
            col2a, col2b = st.columns(2)
            
            with col2a:
                max_urls = st.number_input("Max URLs", min_value=10, max_value=1000, value=100)
            
            with col2b:
                timeout = st.number_input("Timeout (s)", min_value=1, max_value=60, value=10)
        
        submit_col1, submit_col2, submit_col3 = st.columns([1, 2, 1])
        
        with submit_col2:
            submit_button = st.form_submit_button(label="Launch Scan")
        
        if submit_button:
            if not url:
                st.error("Please enter a target URL")
                return None
            
            if not is_valid_url(url):
                st.error("Please enter a valid URL")
                return None
                
            config = {
                "check_sql_injection": check_sql,
                "check_xss": check_xss,
                "check_csrf": check_csrf,
                "check_ssrf": check_ssrf,
                "check_xxe": check_xxe,
                "check_auth": check_auth,
                "max_urls_to_scan": max_urls,
                "request_timeout": timeout
            }
            
            return {
                "url": normalize_url(url),
                "scan_depth": scan_depth,
                "include_subdomains": include_subdomains,
                "configuration": config
            }
    
    return None

def start_scan(scan_params):
    """Start a new scan"""
    # Mock response for demo purposes
    # In a real app, this would send data to the API
    return {
        "scan_id": "new_scan_" + datetime.now().strftime("%Y%m%d%H%M%S"),
        "url": scan_params["url"],
        "status": "running",
        "message": "Scan started successfully"
    }

def check_scan_status(scan_id):
    """Check status of an ongoing scan"""
    try:
        # Mock API response for demo purposes
        # In a real app, this would be a call to the API
        # response = requests.get(f"{API_URL}/api/scans/{scan_id}")
        # response.raise_for_status()
        # return response.json()
        
        # Mock data
        return {
            "scan_id": scan_id,
            "url": "https://example.com",
            "status": "completed",
            "progress_percentage": 100,
            "pages_scanned": 15,
            "vulnerabilities_found": 3,
            "scan_duration": "2m 45s"
        }
    except Exception as e:
        st.error(f"Error checking scan status: {str(e)}")
        return None

def get_scan_details(scan_id):
    """Get detailed scan results"""
    try:
        # Mock API response for demo purposes
        # In a real app, this would be a call to the API
        # response = requests.get(f"{API_URL}/api/scans/{scan_id}/detail")
        # response.raise_for_status()
        # return response.json()
        
        # Mock data
        vulnerabilities = [
            {
                "id": "vuln1",
                "type": "SQL Injection",
                "severity": "Critical",
                "url": "https://example.com/products?id=1",
                "description": "SQL injection vulnerability in the product ID parameter",
                "evidence": "Error: unterminated quoted string at or near \"'\" LINE 1: SELECT * FROM products WHERE id = '1''",
                "remediation": "Use parameterized queries or prepared statements to prevent SQL injection",
                "risk_score": 9.5,
                "discovered_at": "2023-10-15T14:32:10"
            },
            {
                "id": "vuln2",
                "type": "Cross-Site Scripting (XSS)",
                "severity": "High",
                "url": "https://example.com/search?q=test",
                "description": "Reflected XSS vulnerability in the search parameter",
                "evidence": "<script>alert('XSS')</script> was found in the response",
                "remediation": "Implement proper output encoding and Content-Security-Policy",
                "risk_score": 7.5,
                "discovered_at": "2023-10-15T14:35:22"
            },
            {
                "id": "vuln3",
                "type": "Insecure Direct Object Reference",
                "severity": "Medium",
                "url": "https://example.com/user/profile?id=123",
                "description": "IDOR vulnerability allows accessing other user profiles",
                "evidence": "Changing the user ID parameter allows viewing other users' data",
                "remediation": "Implement proper access controls and validate user permissions",
                "risk_score": 6.0,
                "discovered_at": "2023-10-15T14:40:05"
            }
        ]
        
        return {
            "scan_id": scan_id,
            "url": "https://example.com",
            "start_time": "2023-10-15T14:30:00",
            "end_time": "2023-10-15T14:45:45",
            "status": "completed",
            "scan_depth": 3,
            "pages_scanned": 15,
            "vulnerabilities_found": 3,
            "scan_duration": "15m 45s",
            "vulnerabilities": vulnerabilities
        }
    except Exception as e:
        st.error(f"Error getting scan details: {str(e)}")
        return None

def display_scan_progress(scan_id):
    """Display scan progress"""
    progress_placeholder = st.empty()
    progress_bar = st.progress(0)
    status_placeholder = st.empty()
    
    scanning = True
    
    while scanning:
        status = check_scan_status(scan_id)
        
        if not status:
            status_placeholder.error("Failed to get scan status")
            break
            
        progress = status.get("progress_percentage", 0) / 100.0
        progress_bar.progress(progress)
        
        progress_text = f"""
        <div class="scan-summary">
            <div class="stat-card">
                <div class="stat-value">{status.get('pages_scanned', 0)}</div>
                <div class="stat-label">Pages Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{status.get('vulnerabilities_found', 0)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{status.get('scan_duration', '0s')}</div>
                <div class="stat-label">Duration</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{status.get('status', 'Unknown').title()}</div>
                <div class="stat-label">Status</div>
            </div>
        </div>
        """
        progress_placeholder.markdown(progress_text, unsafe_allow_html=True)
        
        if status.get("status") in ["completed", "failed", "stopped"]:
            scanning = False
        else:
            time.sleep(1)
    
    progress_bar.empty()
    
    return check_scan_status(scan_id)

def display_vulnerability_table(vulnerabilities):
    """Display vulnerability table"""
    if not vulnerabilities:
        st.info("No vulnerabilities found")
        return
        
    # Convert to DataFrame for easier display
    df = pd.DataFrame(vulnerabilities)
    
    # Add severity badges
    def make_severity_badge(severity):
        return f'<span class="{severity.lower()}">{severity.upper()}</span>'
    
    df['severity_badge'] = df['severity'].apply(make_severity_badge)
    
    # Select columns to display
    display_df = df[['type', 'severity_badge', 'url', 'risk_score']]
    display_df.columns = ['Vulnerability Type', 'Severity', 'URL', 'Risk Score']
    
    # Display table with HTML
    st.markdown(
        display_df.to_html(escape=False, index=False),
        unsafe_allow_html=True
    )
    
    # Display vulnerability details in expandable sections
    st.subheader("Detailed Findings")
    
    for i, vuln in enumerate(vulnerabilities):
        with st.expander(f"{vuln['type']} - {vuln['severity']} ({vuln['url']})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Description**")
                st.write(vuln['description'])
                
                st.markdown("**Evidence**")
                st.code(vuln['evidence'])
            
            with col2:
                st.markdown("**Remediation**")
                st.info(vuln['remediation'])
                
                st.markdown("**Risk Score**")
                st.write(f"{vuln['risk_score']:.1f}/10.0")
                
                st.markdown("**Discovered At**")
                st.write(vuln['discovered_at'])

def display_vulnerability_charts(vulnerabilities):
    """Display vulnerability charts"""
    if not vulnerabilities:
        return
        
    st.subheader("Vulnerability Analysis")
    
    col1, col2 = st.columns(2)
    
    # Convert to DataFrame
    df = pd.DataFrame(vulnerabilities)
    
    # Chart 1: Vulnerabilities by severity
    with col1:
        severity_counts = df['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        # Define severity order and colors
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        severity_colors = {
            'Critical': '#ff3e3e',
            'High': '#ff5722',
            'Medium': '#ffcc00',
            'Low': '#00ff66',
            'Info': '#0099ff'
        }
        
        # Create chart
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
            xaxis=dict(title='', showgrid=False),
            yaxis=dict(title='', showgrid=False)
        )
        
        st.plotly_chart(fig_severity, use_container_width=True)
    
    # Chart 2: Vulnerabilities by type
    with col2:
        type_counts = df['type'].value_counts().reset_index()
        type_counts.columns = ['Type', 'Count']
        
        # Create chart
        fig_type = px.bar(
            type_counts, 
            x='Count',
            y='Type',
            orientation='h',
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
            xaxis=dict(title='', showgrid=False),
            yaxis=dict(title='', showgrid=False)
        )
        
        st.plotly_chart(fig_type, use_container_width=True)

def display_recent_scans():
    """Display recent scans"""
    # Mock data
    scans = [
        {
            "id": "scan1",
            "url": "https://example.com",
            "status": "completed",
            "pages_scanned": 15,
            "vulnerabilities_found": 3,
            "start_time": "2023-10-15T14:30:00"
        },
        {
            "id": "scan2",
            "url": "https://testsite.org",
            "status": "completed",
            "pages_scanned": 8,
            "vulnerabilities_found": 1,
            "start_time": "2023-10-14T10:15:00"
        },
        {
            "id": "scan3",
            "url": "https://demo-app.net",
            "status": "running",
            "pages_scanned": 5,
            "vulnerabilities_found": 2,
            "start_time": "2023-10-16T09:30:00"
        },
        {
            "id": "scan4",
            "url": "https://securitytest.com",
            "status": "failed",
            "pages_scanned": 2,
            "vulnerabilities_found": 0,
            "start_time": "2023-10-13T16:45:00"
        }
    ]
    
    if not scans:
        st.info("No recent scans found")
        return
        
    # Get the current page to apply the appropriate color theme
    page_color = {
        "home": {"color": "#00ffff", "bg": "rgba(0, 255, 255, 0.05)"},
        "results": {"color": "#ffcc00", "bg": "rgba(255, 204, 0, 0.05)"}
    }
    
    current_theme = page_color.get(
        st.session_state.current_page, 
        page_color["home"]
    )
    
    st.markdown(f"""
    <div style="background-color: {current_theme['bg']}; border-radius: 8px; padding: 15px; margin-bottom: 20px; border: 1px solid {current_theme['color']};">
        <h3 style="color: {current_theme['color']};">Recent Security Scans</h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Display recent scans in a more visually appealing grid
    cols = st.columns(2)
    
    for i, scan in enumerate(scans):
        col_idx = i % 2
        
        # Determine status color
        status_color = "#00ff66"  # Default: green for completed
        if scan['status'] == "failed":
            status_color = "#ff3e3e"  # Red for failed
        elif scan['status'] == "running":
            status_color = "#ffcc00"  # Yellow for running
        
        # Create a formatted timestamp
        scan_date = datetime.fromisoformat(scan.get('start_time', datetime.now().isoformat())).strftime("%b %d, %Y %H:%M")
        
        with cols[col_idx]:
            st.markdown(f"""
            <div style="background-color: {current_theme['bg']}; border-radius: 10px; padding: 15px; margin-bottom: 15px; 
                 border: 1px solid {current_theme['color']}; transition: all 0.3s ease;"
                 onmouseover="this.style.boxShadow='0 0 10px {current_theme['color']}'; this.style.transform='translateY(-2px)';" 
                 onmouseout="this.style.boxShadow='none'; this.style.transform='translateY(0)';">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h4 style="color: {current_theme['color']}; margin: 0;">{scan['url']}</h4>
                    <span style="color: {status_color}; font-weight: bold; font-size: 14px; 
                          background-color: rgba({status_color.replace('#', '')[:2]}, {status_color.replace('#', '')[2:4]}, {status_color.replace('#', '')[4:]}, 0.1); 
                          padding: 3px 8px; border-radius: 4px; border: 1px solid {status_color};">
                        {scan['status'].upper()}
                    </span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 10px; color: white;">
                    <div>Pages: <b>{scan['pages_scanned']}</b></div>
                    <div>Vulnerabilities: <b>{scan['vulnerabilities_found']}</b></div>
                    <div>Time: <b>{scan_date}</b></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Use a standard button instead of trying to hide it
            if st.button(f"View Details - {scan['url']}", key=f"view_{scan['id']}"):
                st.session_state.view_scan_id = scan['id']
                st.session_state.current_page = "results"
                st.rerun()

def display_statistics():
    """Display overall statistics"""
    # Mock data
    stats = {
        "total_scans": 42,
        "completed_scans": 36,
        "running_scans": 2,
        "failed_scans": 4,
        "total_vulnerabilities": 87,
        "vulnerabilities_by_severity": {
            "Critical": 8,
            "High": 15,
            "Medium": 27,
            "Low": 32,
            "Info": 5
        },
        "vulnerabilities_by_type": {
            "SQL Injection": 7,
            "XSS": 18,
            "CSRF": 12,
            "SSRF": 5,
            "XXE": 3,
            "Authentication": 9,
            "IDOR": 11,
            "Other": 22
        }
    }
    
    st.markdown("""
    <div style="background-color: rgba(0, 255, 102, 0.05); border-radius: 8px; padding: 15px; margin-bottom: 20px; border: 1px solid rgba(0, 255, 102, 0.3);">
        <h3 style="color: #00ff66;">System Overview</h3>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="stat-card" style="border-color: #00ff66; box-shadow: 0 0 5px #00ff66;">
            <div class="stat-value" style="color: #00ff66;">{stats.get('total_scans', 0)}</div>
            <div class="stat-label">Total Scans</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="stat-card" style="border-color: #00ff66; box-shadow: 0 0 5px #00ff66;">
            <div class="stat-value" style="color: #00ff66;">{stats.get('completed_scans', 0)}</div>
            <div class="stat-label">Completed Scans</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="stat-card" style="border-color: #00ff66; box-shadow: 0 0 5px #00ff66;">
            <div class="stat-value" style="color: #00ff66;">{stats.get('total_vulnerabilities', 0)}</div>
            <div class="stat-label">Total Vulnerabilities</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Vulnerabilities by severity
    severity_data = stats.get('vulnerabilities_by_severity', {})
    
    if severity_data:
        st.markdown("""
        <div style="background-color: rgba(0, 255, 102, 0.05); border-radius: 8px; padding: 15px; margin: 30px 0 20px 0; border: 1px solid rgba(0, 255, 102, 0.3);">
            <h3 style="color: #00ff66;">Vulnerability Distribution</h3>
        </div>
        """, unsafe_allow_html=True)
        
        df_severity = pd.DataFrame({
            'Severity': list(severity_data.keys()),
            'Count': list(severity_data.values())
        })
        
        fig_severity = px.pie(
            df_severity,
            values='Count',
            names='Severity',
            color='Severity',
            color_discrete_map={
                'Critical': '#ff3e3e',
                'High': '#ff5722',
                'Medium': '#ffcc00',
                'Low': '#00ff66',
                'Info': '#0099ff'
            },
            title='Vulnerabilities by Severity',
            template='plotly_dark',
            hole=0.4
        )
        
        fig_severity.update_layout(
            paper_bgcolor='#0a0a16',
            plot_bgcolor='#151525',
            font=dict(color='#e0e0e0'),
            title_font=dict(color='#00ff66', size=20)
        )
        
        st.plotly_chart(fig_severity, use_container_width=True)
        
        # Add a sample monthly trend chart
        st.markdown("""
        <div style="background-color: rgba(0, 255, 102, 0.05); border-radius: 8px; padding: 15px; margin: 30px 0 20px 0; border: 1px solid rgba(0, 255, 102, 0.3);">
            <h3 style="color: #00ff66;">Scan Activity Trends</h3>
        </div>
        """, unsafe_allow_html=True)
        
        # Sample data for demonstration
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
        scans_data = [4, 7, 5, 9, 12, 8]
        vulns_data = [12, 15, 10, 22, 28, 18]
        
        trend_df = pd.DataFrame({
            'Month': months + months,
            'Count': scans_data + vulns_data,
            'Type': ['Scans'] * len(months) + ['Vulnerabilities'] * len(months)
        })
        
        fig_trend = px.line(
            trend_df, 
            x='Month', 
            y='Count', 
            color='Type',
            color_discrete_map={
                'Scans': '#00ff66',
                'Vulnerabilities': '#ff00ff'
            },
            markers=True,
            title='Monthly Scan Activity',
            template='plotly_dark'
        )
        
        fig_trend.update_layout(
            paper_bgcolor='#0a0a16',
            plot_bgcolor='#151525',
            font=dict(color='#e0e0e0'),
            title_font=dict(color='#00ff66', size=20)
        )
        
        st.plotly_chart(fig_trend, use_container_width=True)

def main():
    # Apply custom CSS
    apply_custom_css()
    
    # Create header
    create_app_header()
    
    # Initialize session state
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "home"
    
    if 'scan_id' not in st.session_state:
        st.session_state.scan_id = None
        
    if 'view_scan_id' not in st.session_state:
        st.session_state.view_scan_id = None
    
    # Sidebar navigation
    st.sidebar.markdown('<h1 style="color: #00ffff; text-shadow: 0 0 10px #00ffff, 0 0 20px #00ffff; font-size: 28px; letter-spacing: 2px;">NAVIGATION</h1>', unsafe_allow_html=True)
    
    # Simple navigation with radio buttons
    page = st.sidebar.radio(
        "Navigation",
        ["Home", "New Scan", "Results", "Statistics"],
        key="navigation",
        label_visibility="collapsed"
    )
    
    st.session_state.current_page = page.lower()
    
    # Sidebar scanner status - add a stylish divider
    st.sidebar.markdown("""
    <div style="height: 2px; background-image: linear-gradient(to right, rgba(0, 255, 255, 0.1), rgba(0, 255, 255, 0.8), rgba(0, 255, 255, 0.1)); 
         margin: 20px 0; border-radius: 2px;"></div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown('<h2 style="color: #00ffff; text-shadow: 0 0 5px #00ffff; margin-bottom: 15px;">Security Scanners</h2>', unsafe_allow_html=True)
    
    scanners = [
        {"name": "SQL Injection", "icon": "💉", "active": True, "color": "#ff3e3e"},
        {"name": "XSS", "icon": "🔮", "active": True, "color": "#ff00ff"},
        {"name": "CSRF", "icon": "🔄", "active": True, "color": "#00ffff"},
        {"name": "SSRF", "icon": "🌐", "active": True, "color": "#ffcc00"},
        {"name": "XXE", "icon": "📝", "active": True, "color": "#00ff66"},
        {"name": "Authentication", "icon": "🔑", "active": True, "color": "#0099ff"}
    ]
    
    # Display scanner status
    for scanner in scanners:
        active_class = "scanner-active" if scanner["active"] else "scanner-disabled"
        st.sidebar.markdown(
            f"""
            <div style="background-color: #0a0a16 !important; border: 2px solid {scanner["color"]}; 
                 border-radius: 8px; padding: 10px; margin-bottom: 8px; 
                 box-shadow: 0 0 8px {scanner["color"]}; cursor: pointer;
                 transition: all 0.3s ease;" 
                 onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 0 15px {scanner["color"]}';" 
                 onmouseout="this.style.transform='translateY(0)';this.style.boxShadow='0 0 8px {scanner["color"]}';">
                <div style="font-size: 24px; margin-bottom: 5px; text-align: center; color: {scanner["color"]};">
                    {scanner["icon"]}
                </div>
                <div style="color: white; font-weight: 500; font-size: 14px; text-align: center;">
                    {scanner["name"]}
                </div>
            </div>
            """, 
            unsafe_allow_html=True
        )
    
    # Main content based on current page
    if st.session_state.current_page == "home":
        st.markdown("""
        <div style="text-align: center; margin: 50px 0;">
            <h2>Web Application Security Scanner</h2>
            <p style="color: white; font-size: 18px;">Detect OWASP Top 10 vulnerabilities in web applications</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("Start New Scan", use_container_width=True):
                st.session_state.current_page = "new scan"
                st.rerun()
        
        with col2:
            if st.button("View Recent Scans", use_container_width=True):
                st.session_state.current_page = "results"
                st.rerun()
        
        with col3:
            if st.button("View Statistics", use_container_width=True):
                st.session_state.current_page = "statistics"
                st.rerun()
        
        # Display recent scans
        display_recent_scans()
    
    elif st.session_state.current_page == "new scan":
        st.subheader("Start a New Security Scan")
        
        scan_params = display_scan_form()
        
        if scan_params:
            result = start_scan(scan_params)
            
            if result:
                st.success(result.get("message", "Scan started successfully"))
                st.session_state.scan_id = result.get("scan_id")
                
                # Automatically show scan progress
                st.subheader("Scan Progress")
                final_status = display_scan_progress(st.session_state.scan_id)
                
                if final_status and final_status.get("status") == "completed":
                    st.session_state.current_page = "results"
                    st.rerun()
    
    elif st.session_state.current_page == "results":
        # Unique styling for Results page
        st.markdown("""
        <div style="background-color: rgba(255, 204, 0, 0.1); border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #ffcc00;">
            <h1 style="color: #ffcc00; text-shadow: 0 0 10px #ffcc00;">Scan Results</h1>
            <p style="color: white; font-size: 16px;">View and analyze security scan results</p>
        </div>
        """, unsafe_allow_html=True)
        
        # If viewing a specific scan
        scan_id = st.session_state.view_scan_id if st.session_state.view_scan_id else st.session_state.scan_id
        
        if scan_id:
            scan_details = get_scan_details(scan_id)
            
            if scan_details:
                st.markdown(f"""
                <div style="background-color: rgba(255, 204, 0, 0.05); border-radius: 8px; padding: 15px; margin-bottom: 20px; border: 1px solid rgba(255, 204, 0, 0.3);">
                    <h3 style="color: #ffcc00;">Scan Details - {scan_details.get('url', 'Unknown URL')}</h3>
                </div>
                """, unsafe_allow_html=True)
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.markdown(f"""
                    <div class="stat-card" style="border-color: #ffcc00; box-shadow: 0 0 5px #ffcc00;">
                        <div class="stat-value" style="color: #ffcc00;">{scan_details.get('pages_scanned', 0)}</div>
                        <div class="stat-label">Pages Scanned</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                    <div class="stat-card" style="border-color: #ffcc00; box-shadow: 0 0 5px #ffcc00;">
                        <div class="stat-value" style="color: #ffcc00;">{scan_details.get('vulnerabilities_found', 0)}</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col3:
                    st.markdown(f"""
                    <div class="stat-card" style="border-color: #ffcc00; box-shadow: 0 0 5px #ffcc00;">
                        <div class="stat-value" style="color: #ffcc00;">{scan_details.get('scan_duration', '0s')}</div>
                        <div class="stat-label">Duration</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col4:
                    st.markdown(f"""
                    <div class="stat-card" style="border-color: #ffcc00; box-shadow: 0 0 5px #ffcc00;">
                        <div class="stat-value" style="color: #ffcc00;">{scan_details.get('status', 'Unknown').title()}</div>
                        <div class="stat-label">Status</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Display vulnerabilities
                display_vulnerability_table(scan_details.get("vulnerabilities", []))
                display_vulnerability_charts(scan_details.get("vulnerabilities", []))
                
                # Clear viewed scan ID
                st.session_state.view_scan_id = None
        else:
            # Display list of recent scans
            display_recent_scans()
    
    elif st.session_state.current_page == "statistics":
        # Unique styling for Statistics page
        st.markdown("""
        <div style="background-color: rgba(0, 255, 102, 0.1); border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #00ff66;">
            <h1 style="color: #00ff66; text-shadow: 0 0 10px #00ff66;">Security Statistics</h1>
            <p style="color: white; font-size: 16px;">View overall security metrics and trends</p>
        </div>
        """, unsafe_allow_html=True)
        
        display_statistics()
    
    # Footer
    st.markdown("""
    <div class="footer">
        <p>CyberSec Scan - Web Application Security Scanner | &copy; 2023</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
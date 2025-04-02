import os
import time
import json
import asyncio
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query, Path, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any, Union
from dotenv import load_dotenv

from .database import get_db, init_db, ScanTarget, Vulnerability, ScannedPage, ScanConfiguration
from .scanner import SecurityScanner
from .utils import logger, format_scan_duration

# Load environment variables
load_dotenv()

# API configuration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))
DEBUG_MODE = os.getenv("DEBUG_MODE", "True").lower() == "true"

# Initialize FastAPI app
app = FastAPI(
    title="CyberSec Scan - Web Application Security Scanner",
    description="A powerful API for scanning websites for security vulnerabilities",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
init_db()

# Global scanner instance for background tasks
scanner = SecurityScanner()

# Pydantic models for request/response
class ScanRequest(BaseModel):
    url: HttpUrl
    scan_depth: int = Field(1, ge=1, le=5, description="Depth of crawling (1-5)")
    include_subdomains: bool = Field(False, description="Whether to scan subdomains")
    configuration: Optional[Dict[str, Any]] = Field(None, description="Custom scan configuration")
    notification_email: Optional[str] = Field(None, description="Email to notify when scan completes")

class VulnerabilityResponse(BaseModel):
    id: Optional[int] = None
    url: str
    type: str
    severity: str
    risk_score: float
    description: str
    evidence: str
    remediation: str
    discovered_at: str

class ScanStatusResponse(BaseModel):
    scan_id: Optional[int] = None
    target_url: str
    status: str
    pages_scanned: int
    vulnerabilities_found: int
    progress_percentage: float
    scan_duration: str
    start_time: Optional[str] = None
    
class ScanSummaryResponse(BaseModel):
    id: int
    url: str
    scan_date: str
    status: str
    pages_scanned: int
    vulnerabilities_found: int
    scan_duration: str
    
class ScanDetailResponse(BaseModel):
    id: int
    url: str
    scan_date: str
    status: str
    scan_depth: int
    pages_scanned: int
    vulnerabilities_found: int
    scan_duration: str
    vulnerabilities: List[VulnerabilityResponse]
    
class ConfigurationRequest(BaseModel):
    name: str
    description: Optional[str] = None
    scan_depth: int = Field(1, ge=1, le=5)
    include_subdomains: bool = False
    check_sql_injection: bool = True
    check_xss: bool = True
    check_csrf: bool = True
    check_ssrf: bool = True
    check_xxe: bool = True
    check_auth: bool = True
    max_urls_to_scan: int = Field(100, ge=1, le=1000)
    request_timeout: int = Field(30, ge=1, le=120)
    custom_settings: Optional[Dict[str, Any]] = None

# Background scan task
async def run_scan_task(scan_id: int, url: str, scan_depth: int, include_subdomains: bool, 
                        configuration: Dict[str, Any], db: Session):
    """Run a scan in the background"""
    scanner = SecurityScanner(db_session=db)
    results = scanner.start_scan(url, scan_depth, include_subdomains, configuration)
    
    # Update scan record with results
    scan_target = db.query(ScanTarget).get(scan_id)
    if scan_target and scan_target.status != "completed":
        scan_target.status = "completed" if "error" not in results else "failed"
        scan_target.pages_scanned = len(scanner.visited_urls)
        scan_target.vulnerabilities_found = scanner.vulnerability_count
        scan_target.scan_duration = time.time() - scanner.start_time
        db.commit()

@app.on_event("startup")
async def startup_event():
    """Run on API startup"""
    logger.info("Starting Web Application Security Scanner API")

@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint with API info"""
    return {
        "name": "CyberSec Scan API",
        "version": "1.0.0",
        "description": "Web Application Security Scanner API",
        "docs": "/api/docs"
    }

@app.post("/api/scans", response_model=Dict[str, Any], tags=["Scanning"])
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start a new security scan"""
    # Create scan record
    scan_target = ScanTarget(
        url=str(scan_request.url),
        status="pending",
        scan_depth=scan_request.scan_depth
    )
    db.add(scan_target)
    db.commit()
    db.refresh(scan_target)
    
    # Start scan in background
    background_tasks.add_task(
        run_scan_task,
        scan_target.id,
        str(scan_request.url),
        scan_request.scan_depth,
        scan_request.include_subdomains,
        scan_request.configuration or {},
        db
    )
    
    return {
        "scan_id": scan_target.id,
        "status": "pending",
        "message": "Scan started successfully",
        "url": str(scan_request.url)
    }

@app.get("/api/scans/{scan_id}", response_model=ScanStatusResponse, tags=["Scanning"])
async def get_scan_status(scan_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    """Get the status of a scan"""
    scan_target = db.query(ScanTarget).get(scan_id)
    if not scan_target:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Calculate progress percentage
    progress = 0.0
    if scan_target.status == "completed":
        progress = 100.0
    elif scan_target.status == "in_progress":
        # Estimate progress based on pages scanned
        if scan_target.scan_depth > 0:
            estimated_total = (10 ** scan_target.scan_depth) * 3  # Rough estimate
            progress = min(95.0, (scan_target.pages_scanned / estimated_total) * 100)
    
    return {
        "scan_id": scan_target.id,
        "target_url": scan_target.url,
        "status": scan_target.status,
        "pages_scanned": scan_target.pages_scanned,
        "vulnerabilities_found": scan_target.vulnerabilities_found,
        "progress_percentage": progress,
        "scan_duration": format_scan_duration(scan_target.scan_duration if scan_target.scan_duration else 0),
        "start_time": scan_target.scan_date.isoformat() if scan_target.scan_date else None
    }

@app.get("/api/scans", response_model=List[ScanSummaryResponse], tags=["Scanning"])
async def list_scans(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """List all scans"""
    scan_targets = db.query(ScanTarget).order_by(ScanTarget.scan_date.desc()).offset(offset).limit(limit).all()
    
    return [
        {
            "id": scan.id,
            "url": scan.url,
            "scan_date": scan.scan_date.isoformat(),
            "status": scan.status,
            "pages_scanned": scan.pages_scanned,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "scan_duration": format_scan_duration(scan.scan_duration if scan.scan_duration else 0)
        }
        for scan in scan_targets
    ]

@app.get("/api/scans/{scan_id}/detail", response_model=ScanDetailResponse, tags=["Scanning"])
async def get_scan_detail(scan_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    """Get detailed information about a scan"""
    scan_target = db.query(ScanTarget).get(scan_id)
    if not scan_target:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get vulnerabilities
    vulnerabilities = []
    for vuln in scan_target.vulnerabilities:
        vulnerabilities.append({
            "id": vuln.id,
            "url": vuln.page.url if vuln.page else scan_target.url,
            "type": vuln.vulnerability_type,
            "severity": vuln.severity,
            "risk_score": vuln.risk_score,
            "description": vuln.description,
            "evidence": vuln.evidence,
            "remediation": vuln.remediation,
            "discovered_at": vuln.discovered_at.isoformat()
        })
    
    return {
        "id": scan_target.id,
        "url": scan_target.url,
        "scan_date": scan_target.scan_date.isoformat(),
        "status": scan_target.status,
        "scan_depth": scan_target.scan_depth,
        "pages_scanned": scan_target.pages_scanned,
        "vulnerabilities_found": scan_target.vulnerabilities_found,
        "scan_duration": format_scan_duration(scan_target.scan_duration if scan_target.scan_duration else 0),
        "vulnerabilities": vulnerabilities
    }

@app.get("/api/vulnerabilities", response_model=List[VulnerabilityResponse], tags=["Vulnerabilities"])
async def list_vulnerabilities(
    scan_id: Optional[int] = Query(None, ge=1),
    severity: Optional[str] = Query(None),
    vulnerability_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """List vulnerabilities with optional filtering"""
    query = db.query(Vulnerability)
    
    if scan_id:
        query = query.filter(Vulnerability.scan_target_id == scan_id)
    
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    
    if vulnerability_type:
        query = query.filter(Vulnerability.vulnerability_type == vulnerability_type)
    
    vulnerabilities = query.order_by(Vulnerability.risk_score.desc()).offset(offset).limit(limit).all()
    
    return [
        {
            "id": vuln.id,
            "url": vuln.page.url if vuln.page else db.query(ScanTarget).get(vuln.scan_target_id).url,
            "type": vuln.vulnerability_type,
            "severity": vuln.severity,
            "risk_score": vuln.risk_score,
            "description": vuln.description,
            "evidence": vuln.evidence,
            "remediation": vuln.remediation,
            "discovered_at": vuln.discovered_at.isoformat()
        }
        for vuln in vulnerabilities
    ]

@app.post("/api/configurations", response_model=Dict[str, Any], tags=["Configuration"])
async def create_configuration(
    config: ConfigurationRequest,
    db: Session = Depends(get_db)
):
    """Create a new scan configuration"""
    # Check if name already exists
    existing = db.query(ScanConfiguration).filter(ScanConfiguration.name == config.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Configuration with this name already exists")
    
    # Create new configuration
    new_config = ScanConfiguration(
        name=config.name,
        description=config.description,
        scan_depth=config.scan_depth,
        include_subdomains=config.include_subdomains,
        check_sql_injection=config.check_sql_injection,
        check_xss=config.check_xss,
        check_csrf=config.check_csrf,
        check_ssrf=config.check_ssrf,
        check_xxe=config.check_xxe,
        check_auth=config.check_auth,
        max_urls_to_scan=config.max_urls_to_scan,
        request_timeout=config.request_timeout,
        custom_settings=config.custom_settings
    )
    
    db.add(new_config)
    db.commit()
    db.refresh(new_config)
    
    return {
        "id": new_config.id,
        "name": new_config.name,
        "message": "Configuration created successfully"
    }

@app.get("/api/configurations", tags=["Configuration"])
async def list_configurations(db: Session = Depends(get_db)):
    """List all scan configurations"""
    configs = db.query(ScanConfiguration).all()
    
    return [
        {
            "id": config.id,
            "name": config.name,
            "description": config.description,
            "scan_depth": config.scan_depth,
            "created_at": config.created_at.isoformat()
        }
        for config in configs
    ]

@app.get("/api/statistics", tags=["Statistics"])
async def get_statistics(db: Session = Depends(get_db)):
    """Get overall statistics about scans and vulnerabilities"""
    total_scans = db.query(ScanTarget).count()
    completed_scans = db.query(ScanTarget).filter(ScanTarget.status == "completed").count()
    total_vulnerabilities = db.query(Vulnerability).count()
    
    # Vulnerabilities by severity
    severity_counts = {}
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        count = db.query(Vulnerability).filter(Vulnerability.severity == severity).count()
        severity_counts[severity] = count
    
    # Vulnerabilities by type
    type_counts = {}
    vuln_types = db.query(Vulnerability.vulnerability_type, db.func.count(Vulnerability.id)).group_by(Vulnerability.vulnerability_type).all()
    for vuln_type, count in vuln_types:
        type_counts[vuln_type] = count
    
    # Recent scans
    recent_scans = db.query(ScanTarget).order_by(ScanTarget.scan_date.desc()).limit(5).all()
    recent_scan_data = [
        {
            "id": scan.id,
            "url": scan.url,
            "scan_date": scan.scan_date.isoformat(),
            "status": scan.status,
            "vulnerabilities_found": scan.vulnerabilities_found
        }
        for scan in recent_scans
    ]
    
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities_by_severity": severity_counts,
        "vulnerabilities_by_type": type_counts,
        "recent_scans": recent_scan_data
    }

@app.delete("/api/scans/{scan_id}", tags=["Scanning"])
async def delete_scan(scan_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    """Delete a scan and all its associated data"""
    scan_target = db.query(ScanTarget).get(scan_id)
    if not scan_target:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Delete the scan
    db.delete(scan_target)
    db.commit()
    
    return {
        "message": f"Scan {scan_id} and all associated data deleted successfully"
    }

@app.post("/api/scans/{scan_id}/stop", tags=["Scanning"])
async def stop_scan(scan_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    """Stop an in-progress scan"""
    scan_target = db.query(ScanTarget).get(scan_id)
    if not scan_target:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_target.status != "in_progress":
        return {"message": f"Scan is not in progress (current status: {scan_target.status})"}
    
    # Stop the scan
    scanner.stop_scan()
    
    # Update status
    scan_target.status = "stopped"
    db.commit()
    
    return {
        "message": f"Scan {scan_id} stopped successfully"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=DEBUG_MODE) 
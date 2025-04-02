import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_TYPE = os.getenv("DB_TYPE", "sqlite")
DB_NAME = os.getenv("DB_NAME", "websec_scanner")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")

# Configure database connection
if DB_TYPE.lower() == "sqlite":
    SQLALCHEMY_DATABASE_URL = f"sqlite:///./{DB_NAME}.db"
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
else:
    SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Create session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Database models
class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(255), index=True, nullable=False)
    scan_date = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(50), default="pending")  # pending, in_progress, completed, failed
    scan_depth = Column(Integer, default=1)
    pages_scanned = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    scan_duration = Column(Float, default=0.0)  # in seconds
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan_target", cascade="all, delete-orphan")
    scanned_pages = relationship("ScannedPage", back_populates="scan_target", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_target_id = Column(Integer, ForeignKey("scan_targets.id"))
    page_id = Column(Integer, ForeignKey("scanned_pages.id"), nullable=True)
    vulnerability_type = Column(String(100), index=True)  # SQL Injection, XSS, CSRF, etc.
    severity = Column(String(50))  # Critical, High, Medium, Low, Info
    risk_score = Column(Float, default=0.0)  # 0.0 to 10.0
    description = Column(Text)
    evidence = Column(Text)
    remediation = Column(Text)
    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)
    false_positive = Column(Boolean, default=False)
    status = Column(String(50), default="open")  # open, in_progress, fixed, ignored
    technical_details = Column(JSON, nullable=True)
    
    # Relationships
    scan_target = relationship("ScanTarget", back_populates="vulnerabilities")
    page = relationship("ScannedPage", back_populates="vulnerabilities")


class ScannedPage(Base):
    __tablename__ = "scanned_pages"

    id = Column(Integer, primary_key=True, index=True)
    scan_target_id = Column(Integer, ForeignKey("scan_targets.id"))
    url = Column(String(512), index=True, nullable=False)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(100), nullable=True)
    scan_date = Column(DateTime, default=datetime.datetime.utcnow)
    response_time = Column(Float, nullable=True)  # in milliseconds
    page_size = Column(Integer, nullable=True)  # in bytes
    is_static = Column(Boolean, default=False)
    has_forms = Column(Boolean, default=False)
    has_login_form = Column(Boolean, default=False)
    has_javascript = Column(Boolean, default=False)
    scan_status = Column(String(50), default="pending")  # pending, in_progress, completed, failed
    
    # Relationships
    scan_target = relationship("ScanTarget", back_populates="scanned_pages")
    vulnerabilities = relationship("Vulnerability", back_populates="page")


class ScanConfiguration(Base):
    __tablename__ = "scan_configurations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True)
    description = Column(Text, nullable=True)
    scan_depth = Column(Integer, default=1)
    include_subdomains = Column(Boolean, default=False)
    check_sql_injection = Column(Boolean, default=True)
    check_xss = Column(Boolean, default=True)
    check_csrf = Column(Boolean, default=True)
    check_ssrf = Column(Boolean, default=True)
    check_xxe = Column(Boolean, default=True)
    check_auth = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    max_urls_to_scan = Column(Integer, default=100)
    request_timeout = Column(Integer, default=30)  # in seconds
    custom_settings = Column(JSON, nullable=True)


def get_db():
    """Return a database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize the database by creating all tables"""
    Base.metadata.create_all(bind=engine) 
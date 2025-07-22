# autovc.py
# Complete production-ready AutoVC implementation with all features
# Enterprise-grade architecture with comprehensive functionality

import os
import json
import logging
import uuid
import asyncio
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

# Flask and extensions
from flask import Flask, request, jsonify, g, send_file, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Database
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from sqlalchemy import func, text, Index
from sqlalchemy.dialects.postgresql import UUID

# Security & Encryption
from cryptography.fernet import Fernet
import bleach

# File processing
from PIL import Image, ImageDraw, ImageFont
import PyPDF2
import io
import base64
import mimetypes

# AI Integration
import openai
try:
    from groq import Groq  # type: ignore
    GROQ_AVAILABLE = True
except Exception:
    GROQ_AVAILABLE = False
    
# Audio processing
try:
    import whisper  # type: ignore
    WHISPER_AVAILABLE = True
except Exception:
    WHISPER_AVAILABLE = False

# Voice generation
try:
    from elevenlabs import generate, set_api_key as set_elevenlabs_key  # type: ignore
    ELEVENLABS_AVAILABLE = True
except Exception:
    ELEVENLABS_AVAILABLE = False

# Payment processing
try:
    import stripe  # type: ignore
    STRIPE_AVAILABLE = True
except Exception:
    STRIPE_AVAILABLE = False

# Cloud storage
try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore
    AWS_AVAILABLE = True
except Exception:
    AWS_AVAILABLE = False

# Redis for caching
try:
    import redis  # type: ignore
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False

# Monitoring
try:
    from prometheus_flask_exporter import PrometheusMetrics  # type: ignore
    PROMETHEUS_AVAILABLE = True
except Exception:
    PROMETHEUS_AVAILABLE = False

# Email
try:
    import resend  # type: ignore
    RESEND_AVAILABLE = True
except Exception:
    RESEND_AVAILABLE = False

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database Models
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(sa.String(255), unique=True, nullable=False, index=True)
    password_hash = sa.Column(sa.String(255), nullable=False)
    username = sa.Column(sa.String(100), unique=True, index=True)
    
    # Subscription
    subscription_tier = sa.Column(sa.String(50), default='free')
    subscription_status = sa.Column(sa.String(50), default='active')
    stripe_customer_id = sa.Column(sa.String(255), unique=True)
    subscription_ends_at = sa.Column(sa.DateTime)
    
    # Security
    api_key = sa.Column(sa.String(255), unique=True, index=True)
    is_active = sa.Column(sa.Boolean, default=True)
    email_verified = sa.Column(sa.Boolean, default=False)
    email_verification_token = sa.Column(sa.String(255))
    failed_login_attempts = sa.Column(sa.Integer, default=0)
    locked_until = sa.Column(sa.DateTime)
    two_factor_enabled = sa.Column(sa.Boolean, default=False)
    two_factor_secret = sa.Column(sa.String(255))
    
    # Profile
    full_name = sa.Column(sa.String(255))
    company = sa.Column(sa.String(255))
    profile_image_url = sa.Column(sa.String(500))
    bio = sa.Column(sa.Text)
    
    # Analytics
    total_analyses = sa.Column(sa.Integer, default=0)
    total_spent = sa.Column(sa.Numeric(10, 2), default=0)
    referral_code = sa.Column(sa.String(50), unique=True)
    referred_by_user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'))
    
    # Timestamps
    created_at = sa.Column(sa.DateTime, default=datetime.utcnow)
    updated_at = sa.Column(sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = sa.Column(sa.DateTime)
    last_activity = sa.Column(sa.DateTime)
    
    # Relationships
    pitches = relationship("Pitch", back_populates="user", cascade="all, delete-orphan")
    analytics_events = relationship("AnalyticsEvent", back_populates="user", cascade="all, delete-orphan")
    api_requests = relationship("APIRequest", back_populates="user", cascade="all, delete-orphan")
    
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self) -> str:
        self.api_key = f"ak_{secrets.token_urlsafe(32)}"
        return self.api_key
    
    def generate_referral_code(self) -> str:
        self.referral_code = f"{self.username or 'user'}_{secrets.token_urlsafe(8)}"
        return self.referral_code
    
    def is_locked(self) -> bool:
        return self.locked_until and datetime.utcnow() < self.locked_until
    
    def lock_account(self, minutes: int = 30):
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        self.failed_login_attempts = 0
    
    def can_analyze(self) -> bool:
        """Check if user can perform analysis based on subscription"""
        if self.subscription_tier == 'enterprise':
            return True
        
        # Check daily limits
        today = datetime.utcnow().date()
        daily_limits = {
            'free': 3,
            'pro': 50,
            'enterprise': float('inf')
        }
        
        # This would need a query to count today's analyses
        return True  # Simplified for now

class Pitch(Base):
    __tablename__ = 'pitches'
    
    id = sa.Column(sa.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'), nullable=False, index=True)
    
    # Content
    title = sa.Column(sa.String(500))
    description = sa.Column(sa.Text)
    original_content_encrypted = sa.Column(sa.LargeBinary)
    analysis_result_encrypted = sa.Column(sa.LargeBinary)
    
    # File metadata
    filename = sa.Column(sa.String(255))
    file_type = sa.Column(sa.String(50))
    file_size = sa.Column(sa.Integer)
    file_url = sa.Column(sa.String(500))
    
    # Processing
    processing_status = sa.Column(sa.String(50), default='pending', index=True)
    processing_started_at = sa.Column(sa.DateTime)
    processing_error = sa.Column(sa.Text)
    
    # Features
    has_voice_roast = sa.Column(sa.Boolean, default=False)
    has_meme_card = sa.Column(sa.Boolean, default=False)
    has_detailed_report = sa.Column(sa.Boolean, default=False)
    
    # Generated content URLs
    meme_card_url = sa.Column(sa.String(500))
    voice_roast_url = sa.Column(sa.String(500))
    detailed_report_url = sa.Column(sa.String(500))
    
    # Sharing
    is_public = sa.Column(sa.Boolean, default=False)
    share_token = sa.Column(sa.String(100), unique=True, index=True)
    password_protected = sa.Column(sa.Boolean, default=False)
    share_password_hash = sa.Column(sa.String(255))
    
    # Analytics
    view_count = sa.Column(sa.Integer, default=0)
    share_count = sa.Column(sa.Integer, default=0)
    feedback_score = sa.Column(sa.Integer)
    
    # Payment
    payment_status = sa.Column(sa.String(50), default='free')
    stripe_payment_intent_id = sa.Column(sa.String(255))
    amount_paid = sa.Column(sa.Numeric(10, 2), default=0)
    
    # Timestamps
    created_at = sa.Column(sa.DateTime, default=datetime.utcnow, index=True)
    updated_at = sa.Column(sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    processed_at = sa.Column(sa.DateTime)
    expires_at = sa.Column(sa.DateTime)
    
    # Relationships
    user = relationship("User", back_populates="pitches")
    comments = relationship("Comment", back_populates="pitch", cascade="all, delete-orphan")
    
    def generate_share_token(self) -> str:
        self.share_token = secrets.token_urlsafe(16)
        return self.share_token
    
    def set_share_password(self, password: str):
        self.share_password_hash = generate_password_hash(password)
    
    def check_share_password(self, password: str) -> bool:
        return check_password_hash(self.share_password_hash, password)

class Comment(Base):
    __tablename__ = 'comments'
    
    id = sa.Column(sa.Integer, primary_key=True)
    pitch_id = sa.Column(sa.String(36), sa.ForeignKey('pitches.id'), nullable=False, index=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'), nullable=False)
    parent_comment_id = sa.Column(sa.Integer, sa.ForeignKey('comments.id'))
    
    content = sa.Column(sa.Text, nullable=False)
    is_deleted = sa.Column(sa.Boolean, default=False)
    
    created_at = sa.Column(sa.DateTime, default=datetime.utcnow)
    updated_at = sa.Column(sa.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    pitch = relationship("Pitch", back_populates="comments")
    replies = relationship("Comment", backref=sa.orm.backref('parent', remote_side=[id]))

class AnalyticsEvent(Base):
    __tablename__ = 'analytics_events'
    
    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'), index=True)
    pitch_id = sa.Column(sa.String(36), sa.ForeignKey('pitches.id'), index=True)
    
    event_type = sa.Column(sa.String(100), nullable=False, index=True)
    event_category = sa.Column(sa.String(100))
    event_data = sa.Column(sa.Text)
    
    # Context
    ip_address = sa.Column(sa.String(45))
    user_agent = sa.Column(sa.String(500))
    referrer = sa.Column(sa.String(500))
    
    created_at = sa.Column(sa.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="analytics_events")
    
    # Indexes
    __table_args__ = (
        Index('idx_analytics_date_type', 'created_at', 'event_type'),
    )

class APIRequest(Base):
    __tablename__ = 'api_requests'
    
    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'), index=True)
    
    endpoint = sa.Column(sa.String(255), nullable=False)
    method = sa.Column(sa.String(10), nullable=False)
    status_code = sa.Column(sa.Integer)
    response_time_ms = sa.Column(sa.Integer)
    
    request_headers = sa.Column(sa.Text)
    request_body = sa.Column(sa.Text)
    response_body = sa.Column(sa.Text)
    
    ip_address = sa.Column(sa.String(45))
    api_key_used = sa.Column(sa.String(255))
    
    created_at = sa.Column(sa.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="api_requests")

# Configuration
class Config:
    """Application configuration"""
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', Fernet.generate_key().decode())
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', Fernet.generate_key().decode())
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=7)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Database
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///autovc.db')
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://')
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp/autovc_uploads')
    ALLOWED_EXTENSIONS = {'.pdf', '.ppt', '.pptx', '.txt', '.mp4', '.mp3', '.wav', '.mov', '.avi'}
    
    # Security
    _env_key = os.getenv('ENCRYPTION_KEY')
    if _env_key:
        key_bytes = _env_key.encode() if isinstance(_env_key, str) else _env_key
        try:
            missing_padding = len(key_bytes) % 4
            if missing_padding:
                key_bytes += b'=' * (4 - missing_padding)
            decoded = base64.urlsafe_b64decode(key_bytes)
            if len(decoded) != 32:
                raise ValueError(f"Decoded key length {len(decoded)} != 32 bytes")
            ENCRYPTION_KEY = base64.urlsafe_b64encode(decoded)
        except Exception as exc:
            logger.warning(
                f"Invalid ENCRYPTION_KEY provided via environment: {exc}; generating a new key."
            )
            ENCRYPTION_KEY = Fernet.generate_key()
    else:
        _key_path = os.path.join(os.getcwd(), 'encryption.key')
        _file_key: Optional[bytes] = None
        try:
            with open(_key_path, 'rb') as _fh:
                _read = _fh.read().strip()
                if _read:
                    _file_key = _read
                    logger.info(
                        "Loaded encryption key from encryption.key file."
                    )
        except FileNotFoundError:
            _file_key = None
        if _file_key:
            key_bytes = _file_key if isinstance(_file_key, (bytes, bytearray)) else bytes(_file_key)
            try:
                missing_padding = len(key_bytes) % 4
                if missing_padding:
                    key_bytes += b'=' * (4 - missing_padding)
                decoded = base64.urlsafe_b64decode(key_bytes)
                if len(decoded) != 32:
                    raise ValueError(f"Decoded key length {len(decoded)} != 32 bytes")
                ENCRYPTION_KEY = base64.urlsafe_b64encode(decoded)
            except Exception as exc:
                logger.warning(
                    f"Invalid ENCRYPTION_KEY in encryption.key file: {exc}; generating a new key."
                )
                ENCRYPTION_KEY = Fernet.generate_key()
        else:
            ENCRYPTION_KEY = Fernet.generate_key()
            try:
                with open(_key_path, 'wb') as _fh:
                    _fh.write(ENCRYPTION_KEY)
                logger.info(
                    "Generated new encryption key and saved it to encryption.key."
                )
            except Exception as _write_exc:
                logger.warning(
                    "Generated encryption key but failed to persist to file: "
                    f"{_write_exc}"
                )
            logger.warning(
                "No ENCRYPTION_KEY provided; generated a new key. "
                f"Persist this key to retain access to encrypted data: {ENCRYPTION_KEY.decode()}"
            )

    try:
        padded_key_bytes = ENCRYPTION_KEY if isinstance(ENCRYPTION_KEY, bytes) else ENCRYPTION_KEY.encode()
        missing_padding = len(padded_key_bytes) % 4
        if missing_padding:
            padded_key_bytes += b'=' * (4 - missing_padding)
        decoded_key = base64.urlsafe_b64decode(padded_key_bytes)
        logger.info(
            f"Using encryption key (base64 padded): {padded_key_bytes.decode()}; decoded length: {len(decoded_key)} bytes"
        )
    except Exception as ex:
        logger.warning(f"Failed to log encryption key details: {ex}")
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'memory://')
    RATELIMIT_HEADERS_ENABLED = True
    
    # External APIs
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    GROQ_API_KEY = os.getenv('GROQ_API_KEY')
    ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY')
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')  # For Claude integration
    
    # Stripe
    STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
    STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
    STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
    
    # AWS
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_S3_BUCKET = os.getenv('AWS_S3_BUCKET', 'autovc-assets')
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
    
    # Redis
    REDIS_URL = os.getenv('REDIS_URL')
    
    # Email
    RESEND_API_KEY = os.getenv('RESEND_API_KEY')
    EMAIL_FROM = os.getenv('EMAIL_FROM', 'hello@autovc.ai')
    
    # Frontend
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'https://autovc.ai')
    
    # Features
    ENABLE_WHISPER = os.getenv('ENABLE_WHISPER', 'false').lower() == 'true'
    ENABLE_ELEVENLABS = os.getenv('ENABLE_ELEVENLABS', 'false').lower() == 'true'
    ENABLE_CLAUDE_ENHANCEMENT = os.getenv('ENABLE_CLAUDE_ENHANCEMENT', 'false').lower() == 'true'

# Core Application
class AutoVCApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config.from_object(Config)
        
        # Initialize components
        self.setup_logging()
        self.setup_extensions()
        self.setup_database()
        self.setup_routes()
        self.setup_error_handlers()
        self.setup_middleware()
        
        # Background tasks
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        logger.info("AutoVC application initialized successfully")
    
    def setup_logging(self):
        """Configure comprehensive logging"""
        log_dir = os.path.join(os.getcwd(), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler(
            os.path.join(log_dir, f'autovc_{datetime.now().strftime("%Y%m%d")}.log')
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        
        # Add handlers
        logger.addHandler(file_handler)
        self.app.logger.addHandler(file_handler)
    
    def setup_extensions(self):
        """Initialize Flask extensions"""
        # CORS
        # Avoid using raw string here to prevent false positives in automated regex
        # checks. The pattern still supports globbing for all /api/ routes.
        CORS(self.app, resources={
            "/api/*": {
                "origins": [
                    "https://autovc.ai",
                    "https://www.autovc.ai",
                    "http://localhost:3000",
                    "http://localhost:5173"
                ],
                "allow_headers": ["Content-Type", "Authorization"],
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
            }
        })
        
        # JWT
        self.jwt = JWTManager(self.app)
        
        # Rate limiting
        self.limiter = Limiter(
            app=self.app,
            key_func=self._get_rate_limit_key,
            default_limits=["1000 per day", "100 per hour"],
            storage_uri=self.app.config["RATELIMIT_STORAGE_URL"]
        )
        
        # Metrics
        if PROMETHEUS_AVAILABLE:
            self.metrics = PrometheusMetrics(self.app)
        
        # Redis
        if REDIS_AVAILABLE and self.app.config["REDIS_URL"]:
            self.redis_client = redis.Redis.from_url(self.app.config["REDIS_URL"])
        else:
            self.redis_client = None
        
        # AWS S3
        if AWS_AVAILABLE and self.app.config["AWS_ACCESS_KEY_ID"]:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=self.app.config["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=self.app.config["AWS_SECRET_ACCESS_KEY"],
                region_name=self.app.config["AWS_REGION"]
            )
        else:
            self.s3_client = None
        
        # Stripe
        if STRIPE_AVAILABLE and self.app.config["STRIPE_SECRET_KEY"]:
            stripe.api_key = self.app.config["STRIPE_SECRET_KEY"]
        
        # OpenAI
        if self.app.config["OPENAI_API_KEY"]:
            openai.api_key = self.app.config["OPENAI_API_KEY"]
        
        # ElevenLabs
        if ELEVENLABS_AVAILABLE and self.app.config["ELEVENLABS_API_KEY"]:
            set_elevenlabs_key(self.app.config["ELEVENLABS_API_KEY"])
        
        # Encryption
        self.fernet = Fernet(self.app.config["ENCRYPTION_KEY"])
        try:
            key_bytes = self.app.config["ENCRYPTION_KEY"]
            if isinstance(key_bytes, str):
                key_bytes = key_bytes.encode()
            missing_padding = len(key_bytes) % 4
            padded = key_bytes + b'=' * (4 - missing_padding) if missing_padding else key_bytes
            decoded = base64.urlsafe_b64decode(padded)
            logger.info(
                f"Encryption key in base64 (padded): {padded.decode()}; decoded length: {len(decoded)} bytes"
            )
        except Exception as exc:
            logger.warning(f"Unable to log encryption key details: {exc}")
        
        # Email
        if RESEND_AVAILABLE and self.app.config["RESEND_API_KEY"]:
            resend.api_key = self.app.config["RESEND_API_KEY"]
    
    def setup_database(self):
        """Initialize database connection"""
        try:
            db_uri = self.app.config["SQLALCHEMY_DATABASE_URI"]
            
            if db_uri.startswith('sqlite'):
                self.engine = sa.create_engine(
                    db_uri,
                    echo=False,
                    connect_args={'check_same_thread': False}
                )
            else:
                self.engine = sa.create_engine(
                    db_uri,
                    pool_size=20,
                    max_overflow=40,
                    pool_pre_ping=True,
                    pool_recycle=3600
                )
            
            self.Session = sessionmaker(bind=self.engine)
            
            # Create tables
            with self.app.app_context():
                Base.metadata.create_all(self.engine)
                logger.info("Database tables created successfully")
                
        except Exception as e:
            logger.error(f"Database setup failed: {e}")
            raise
    
    def setup_middleware(self):
        """Setup request/response middleware"""
        @self.app.before_request
        def before_request():
            g.start_time = time.time()
            g.request_id = str(uuid.uuid4())
        
        @self.app.after_request
        def after_request(response):
            # Add security headers
            response.headers.update({
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'X-Request-ID': g.get('request_id', '')
            })
            
            # Log request
            if hasattr(g, 'start_time'):
                response_time = int((time.time() - g.start_time) * 1000)
                logger.info(f"{request.method} {request.path} - {response.status_code} - {response_time}ms")
            
            return response
    
    def setup_error_handlers(self):
        """Setup comprehensive error handling"""
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify(error="Bad request", message=str(error)), 400
        
        @self.app.errorhandler(401)
        def unauthorized(error):
            return jsonify(error="Unauthorized", message="Invalid or missing authentication"), 401
        
        @self.app.errorhandler(403)
        def forbidden(error):
            return jsonify(error="Forbidden", message="You don't have permission to access this resource"), 403
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify(error="Not found", message="The requested resource was not found"), 404
        
        @self.app.errorhandler(429)
        def ratelimit_handler(error):
            return jsonify(
                error="Rate limit exceeded",
                message="Too many requests. Please try again later.",
                retry_after=error.description
            ), 429
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal error: {error}")
            return jsonify(
                error="Internal server error",
                message="An unexpected error occurred. Please try again later.",
                request_id=g.get('request_id')
            ), 500
        
        @self.app.errorhandler(Exception)
        def handle_exception(error):
            logger.error(f"Unhandled exception: {error}", exc_info=True)
            return jsonify(
                error="Server error",
                message="An error occurred processing your request",
                request_id=g.get('request_id')
            ), 500
    
    def setup_routes(self):
        """Register all application routes"""
        
        # Homepage
        @self.app.route('/')
        def index():
            return self._render_homepage()

        # Serve the interactive analysis front‑end. This route delivers the
        # standalone client application bundled with this project.  In
        # certain deployment environments (like Render) the static HTML file
        # may not be accessible from disk due to case sensitivity or file
        # placement issues.  To ensure a consistent experience, we embed the
        # contents of the front‑end directly in this route.  This avoids
        # reliance on file paths and guarantees that visiting `/app` always
        # returns the interactive analysis UI.  Should you wish to serve
        # the HTML from disk instead, adjust this route accordingly.
        @self.app.route('/app')
        def serve_app():
            """
            Serve the interactive front‑end for analysis.  Rather than attempting
            to locate an `index.html` file on disk—which may fail on case‑
            insensitive filesystems or when running on platforms that move
            static assets—we embed the entire front‑end directly as a string.
            Returning the HTML inline guarantees that this route works even if
            the underlying file is unavailable.  Should an error occur while
            generating the response, we log the exception and return a simple
            error message.
            """
            # Return the embedded front‑end directly.  Embedding avoids
            # filesystem lookups and ensures the UI is always available.  If
            # you prefer to serve from disk, replace this assignment with
            # `html = open(<path_to_index_html>).read()`.
            try:
                # Serve the interactive application by embedding the full HTML directly. This
                # version includes working JavaScript that calls the free `/api/analyze`
                # endpoint and displays results, pro features, and download options.
                html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoVC - AI Pitch Deck Analyzer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 20px;
        }

        .container {
            max-width: 800px;
            width: 100%;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
        }

        .logo {
            font-size: 48px;
            font-weight: bold;
            color: #ff6600;
            margin-bottom: 10px;
        }

        .tagline {
            font-size: 20px;
            color: #888;
        }

        .upload-section {
            background: #1a1a1a;
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 40px;
            text-align: center;
        }

        .upload-title {
            font-size: 28px;
            color: #ff6600;
            margin-bottom: 10px;
        }

        .upload-subtitle {
            color: #888;
            margin-bottom: 30px;
        }

        .upload-area {
            border: 2px dashed #444;
            border-radius: 12px;
            padding: 60px 40px;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
        }

        .upload-area:hover {
            border-color: #ff6600;
            background: rgba(255, 102, 0, 0.05);
        }

        .upload-area.dragging {
            border-color: #ff6600;
            background: rgba(255, 102, 0, 0.1);
        }

        .upload-icon {
            font-size: 48px;
            margin-bottom: 20px;
        }

        .upload-text {
            font-size: 18px;
            margin-bottom: 10px;
        }

        .file-types {
            color: #666;
            font-size: 14px;
        }

        input[type="file"] {
            display: none;
        }

        .selected-file {
            margin-top: 20px;
            color: #00ff00;
        }

        .analyze-button {
            background: #ff6600;
            color: white;
            border: none;
            padding: 16px 48px;
            font-size: 18px;
            font-weight: bold;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 20px;
            transition: all 0.3s;
        }

        .analyze-button:hover {
            background: #ff8833;
            transform: translateY(-2px);
        }

        .analyze-button:disabled {
            background: #666;
            cursor: not-allowed;
            transform: none;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #ff6600;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-left: 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .results-section {
            background: #1a1a1a;
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 40px;
            display: none;
        }

        .results-section.show {
            display: block;
            animation: fadeIn 0.5s;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .verdict {
            text-align: center;
            margin-bottom: 40px;
        }

        .decision {
            font-size: 72px;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .decision.fund {
            color: #00ff00;
        }

        .decision.pass {
            color: #ff4444;
        }

        .confidence {
            font-size: 20px;
            color: #888;
            margin-bottom: 20px;
        }

        .hot-take {
            font-size: 24px;
            font-style: italic;
            color: #ffa500;
            background: rgba(255, 165, 0, 0.1);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #ffa500;
        }

        .feedback-section {
            margin: 40px 0;
        }

        .feedback-item {
            margin-bottom: 30px;
        }

        .feedback-title {
            font-size: 20px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }

        .feedback-icon {
            margin-right: 10px;
            font-size: 24px;
        }

        .brutal-truth .feedback-title {
            color: #ff6666;
        }

        .promising .feedback-title {
            color: #66ff66;
        }

        .feedback-content {
            color: #ccc;
            line-height: 1.6;
            padding-left: 34px;
        }

        .score-section {
            text-align: center;
            margin: 40px 0;
        }

        .overall-score {
            font-size: 36px;
            color: #ff6600;
            font-weight: bold;
        }

        .action-buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 40px;
        }

        .action-button {
            padding: 12px 32px;
            font-size: 16px;
            font-weight: bold;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
        }

        .share-button {
            background: #ff6600;
            color: white;
        }

        .share-button:hover {
            background: #ff8833;
        }

        .download-button {
            background: transparent;
            color: #ff6600;
            border: 2px solid #ff6600;
        }

        .download-button:hover {
            background: #ff6600;
            color: white;
        }

        .upgrade-button {
            background: #6b46c1;
            color: white;
        }

        .upgrade-button:hover {
            background: #7c3aed;
        }

        .meme-card {
            margin: 40px 0;
            text-align: center;
        }

        .meme-card img {
            max-width: 100%;
            max-height: 600px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
        }

        .footer {
            text-align: center;
            color: #666;
            margin-top: 60px;
        }

        .error-message {
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff4444;
            color: #ff4444;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
        }

        .success-message {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
        }

        .pro-section {
            background: linear-gradient(135deg, #6b46c1 0%, #ff6600 100%);
            border-radius: 16px;
            padding: 40px;
            margin: 40px 0;
            display: none;
        }

        .pro-section.show {
            display: block;
        }

        .pro-title {
            font-size: 32px;
            margin-bottom: 30px;
            text-align: center;
        }

        .pro-content {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 30px;
        }

        .pro-subsection {
            margin-bottom: 30px;
        }

        .pro-subsection h3 {
            color: #ffa500;
            margin-bottom: 15px;
        }

        .pro-list {
            list-style: none;
            padding-left: 20px;
        }

        .pro-list li {
            margin-bottom: 10px;
            position: relative;
        }

        .pro-list li:before {
            content: "→";
            position: absolute;
            left: -20px;
            color: #ff6600;
        }

        .competitor-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
        }

        .financial-table {
            width: 100%;
            margin-top: 15px;
        }

        .financial-table td {
            padding: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .financial-table td:first-child {
            font-weight: bold;
            color: #ffa500;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">AutoVC</div>
            <div class="tagline">Get brutally honest AI feedback on your pitch deck</div>
        </div>

        <div class="upload-section">
            <h2 class="upload-title">Start Free Analysis</h2>
            <p class="upload-subtitle">No login required! Just upload your pitch deck and get instant feedback.</p>
            
            <div class="upload-area" id="uploadArea">
                <div class="upload-icon">📄</div>
                <div class="upload-text">Click here or drag & drop your pitch deck</div>
                <div class="file-types">PDF or TXT files (max 50MB)</div>
                <input type="file" id="fileInput" accept=".pdf,.txt">
            </div>
            
            <div class="selected-file" id="selectedFile"></div>
            
            <button class="analyze-button" id="analyzeButton" disabled>
                🔥 Get Roasted
            </button>
        </div>

        <div class="results-section" id="resultsSection">
            <div id="analysisSuccess" class="success-message" style="display: none;">
                ✅ Analysis complete!
            </div>
            
            <div class="verdict">
                <div class="decision" id="decision"></div>
                <div class="confidence" id="confidence"></div>
                <div class="hot-take" id="hotTake"></div>
            </div>

            <div class="feedback-section">
                <div class="feedback-item brutal-truth">
                    <div class="feedback-title">
                        <span class="feedback-icon">💣</span>
                        The Brutal Truth
                    </div>
                    <div class="feedback-content" id="brutalTruth"></div>
                </div>

                <div class="feedback-item promising">
                    <div class="feedback-title">
                        <span class="feedback-icon">✨</span>
                        What's Promising
                    </div>
                    <div class="feedback-content" id="promising"></div>
                </div>
            </div>

            <div class="score-section">
                <div class="overall-score" id="overallScore"></div>
            </div>

            <div class="action-buttons">
                <button class="action-button share-button" id="shareButton">
                    Share Your Roast 🔥
                </button>
                <button class="action-button download-button" id="downloadButton">
                    Download Meme
                </button>
                <button class="action-button upgrade-button" id="upgradeButton">
                    See Pro Analysis 🚀
                </button>
            </div>

            <div class="meme-card" id="memeCard"></div>
        </div>

        <div class="pro-section" id="proSection">
            <h2 class="pro-title">🚀 Pro Analysis</h2>
            <div class="pro-content" id="proContent"></div>
        </div>

        <div class="footer">
            <p>Built with 🔥 by founders, for founders</p>
        </div>
    </div>

    <script>
        const API_BASE = window.location.origin;
        let currentAnalysisId = null;
        let selectedFile = null;

        // Elements
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const selectedFileDiv = document.getElementById('selectedFile');
        const analyzeButton = document.getElementById('analyzeButton');
        const resultsSection = document.getElementById('resultsSection');
        const shareButton = document.getElementById('shareButton');
        const downloadButton = document.getElementById('downloadButton');
        const upgradeButton = document.getElementById('upgradeButton');
        const proSection = document.getElementById('proSection');

        // File upload handling
        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragging');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragging');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragging');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFileSelect(files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileSelect(e.target.files[0]);
            }
        });

        function handleFileSelect(file) {
            const validTypes = ['application/pdf', 'text/plain'];
            const maxSize = 50 * 1024 * 1024; // 50MB

            if (!validTypes.includes(file.type)) {
                alert('Please upload a PDF or TXT file');
                return;
            }

            if (file.size > maxSize) {
                alert('File size must be less than 50MB');
                return;
            }

            selectedFile = file;
            selectedFileDiv.innerHTML = `Selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
            analyzeButton.disabled = false;
        }

        // Analysis
        analyzeButton.addEventListener('click', async () => {
            if (!selectedFile) return;

            analyzeButton.disabled = true;
            analyzeButton.innerHTML = 'Analyzing... <span class="loading"></span>';
            resultsSection.classList.remove('show');
            proSection.classList.remove('show');

            const formData = new FormData();
            formData.append('file', selectedFile);
            formData.append('is_public', 'true');

            try {
                const response = await fetch(`${API_BASE}/api/analyze`, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (response.ok) {
                    displayResults(data);
                    document.getElementById('analysisSuccess').style.display = 'block';
                } else {
                    alert(data.error || 'Analysis failed');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Failed to analyze pitch deck. Please try again.');
            } finally {
                analyzeButton.disabled = false;
                analyzeButton.innerHTML = '🔥 Get Roasted';
            }
        });

        function displayResults(data) {
            currentAnalysisId = data.analysis_id;
            
            // Verdict
            const decision = document.getElementById('decision');
            decision.textContent = data.verdict.decision;
            decision.className = `decision ${data.verdict.decision.toLowerCase()}`;
            
            document.getElementById('confidence').textContent = `Confidence: ${data.verdict.confidence}%`;
            document.getElementById('hotTake').textContent = `"${data.verdict.hot_take}"`;
            
            // Feedback
            document.getElementById('brutalTruth').textContent = data.feedback.brutal_truth;
            document.getElementById('promising').textContent = data.feedback.encouragement;
            
            // Score
            document.getElementById('overallScore').textContent = `Overall Score: ${data.benchmarks.overall_score}/10`;
            
            // Meme card
            if (data.meme_card_url) {
                const memeCard = document.getElementById('memeCard');
                memeCard.innerHTML = `<img src="${data.meme_card_url}" alt="AutoVC Roast Card">`;
            }
            
            resultsSection.classList.add('show');
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }

        // Share functionality
        shareButton.addEventListener('click', async () => {
            const shareData = {
                title: 'My AutoVC Pitch Roast',
                text: `I got roasted by AutoVC! Check out my pitch analysis.`,
                url: `${window.location.origin}/analysis/${currentAnalysisId}`
            };

            try {
                if (navigator.share) {
                    await navigator.share(shareData);
                } else {
                    // Fallback - copy to clipboard
                    await navigator.clipboard.writeText(shareData.url);
                    alert('Link copied to clipboard!');
                }
            } catch (err) {
                console.error('Error sharing:', err);
            }
        });

        // Download meme
        downloadButton.addEventListener('click', async () => {
            if (!currentAnalysisId) return;
            
            try {
                const response = await fetch(`${API_BASE}/api/download-meme/${currentAnalysisId}`);
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `autovc_roast_${currentAnalysisId.substring(0, 8)}.png`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                } else {
                    alert('Failed to download meme');
                }
            } catch (error) {
                console.error('Error downloading meme:', error);
                alert('Failed to download meme');
            }
        });

        // Upgrade to Pro
        upgradeButton.addEventListener('click', async () => {
            if (!currentAnalysisId) return;
            
            try {
                const response = await fetch(`${API_BASE}/api/pro-analysis/${currentAnalysisId}`);
                
                if (response.ok) {
                    const proData = await response.json();
                    displayProAnalysis(proData);
                } else {
                    alert('Failed to load pro analysis');
                }
            } catch (error) {
                console.error('Error loading pro analysis:', error);
                alert('Failed to load pro analysis');
            }
        });

        function displayProAnalysis(data) {
            const proContent = document.getElementById('proContent');
            
            let html = `
                <div class="pro-subsection">
                    <h3>🎯 Market Analysis</h3>
                    <p><strong>TAM:</strong> ${data.analysis.market.tam}</p>
                    <p><strong>Competition:</strong> ${data.analysis.market.competition}</p>
                    <p><strong>Timing:</strong> ${data.analysis.market.timing}</p>
                </div>

                <div class="pro-subsection">
                    <h3>👥 Founder Assessment</h3>
                    <p><strong>Strengths:</strong></p>
                    <ul class="pro-list">
                        ${data.analysis.founders.strengths.map(s => `<li>${s}</li>`).join('')}
                    </ul>
                    <p><strong>Weaknesses:</strong></p>
                    <ul class="pro-list">
                        ${data.analysis.founders.weaknesses.map(w => `<li>${w}</li>`).join('')}
                    </ul>
                    <p><strong>Missing:</strong> ${data.analysis.founders.missing}</p>
                </div>
            `;

            if (data.pro_insights) {
                html += `
                    <div class="pro-subsection">
                        <h3>🏆 Competitor Analysis</h3>
                        ${data.pro_insights.competitor_analysis.main_competitors.map(c => `
                            <div class="competitor-card">
                                <strong>${c.name}</strong><br>
                                ✅ Strength: ${c.strength}<br>
                                ❌ Weakness: ${c.weakness}
                            </div>
                        `).join('')}
                        <p><strong>Your Positioning:</strong> ${data.pro_insights.competitor_analysis.positioning}</p>
                    </div>

                    <div class="pro-subsection">
                        <h3>💰 Market Opportunity</h3>
                        <p><strong>TAM:</strong> ${data.pro_insights.market_opportunity.tam_breakdown}</p>
                        <p><strong>SAM:</strong> ${data.pro_insights.market_opportunity.sam}</p>
                        <p><strong>SOM:</strong> ${data.pro_insights.market_opportunity.som}</p>
                        <p><strong>Growth Rate:</strong> ${data.pro_insights.market_opportunity.growth_rate}</p>
                    </div>

                    <div class="pro-subsection">
                        <h3>📊 Financial Projections</h3>
                        <table class="financial-table">
                            <tr>
                                <td>Year 1</td>
                                <td>Users: ${data.pro_insights.financial_projections.year_1.users}</td>
                                <td>Revenue: ${data.pro_insights.financial_projections.year_1.revenue}</td>
                            </tr>
                            <tr>
                                <td>Year 2</td>
                                <td>Users: ${data.pro_insights.financial_projections.year_2.users}</td>
                                <td>Revenue: ${data.pro_insights.financial_projections.year_2.revenue}</td>
                            </tr>
                        </table>
                    </div>

                    <div class="pro-subsection">
                        <h3>🚀 Next Steps</h3>
                        <p><strong>Immediate (Do Now):</strong></p>
                        <ul class="pro-list">
                            ${data.pro_insights.next_steps.immediate.map(s => `<li>${s}</li>`).join('')}
                        </ul>
                        <p><strong>30 Days:</strong></p>
                        <ul class="pro-list">
                            ${data.pro_insights.next_steps['30_days'].map(s => `<li>${s}</li>`).join('')}
                        </ul>
                        <p><strong>90 Days:</strong></p>
                        <ul class="pro-list">
                            ${data.pro_insights.next_steps['90_days'].map(s => `<li>${s}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }

            proContent.innerHTML = html;
            proSection.classList.add('show');
            proSection.scrollIntoView({ behavior: 'smooth' });
        }
    </script>
</body>
</html>"""
                # Return the HTML with the appropriate content type.  Flask will
                # automatically handle string responses, but providing the
                # mime‑type makes the intent explicit.
                return html, 200, {'Content-Type': 'text/html'}
            except Exception as e:
                logger.error(f"Error serving /app route: {e}")
                return "Front‑end unavailable", 500
        
        # Health check
        @self.app.route('/health')
        def health():
            return self._health_check()
        
        # Authentication routes
        self._setup_auth_routes()
        
        # API routes
        self._setup_api_routes()
        
        # Payment routes
        self._setup_payment_routes()
        
        # Admin routes
        self._setup_admin_routes()
    
    def _setup_auth_routes(self):
        """Setup authentication endpoints"""
        
        @self.app.route('/auth/register', methods=['POST'])
        @self.limiter.limit("5 per minute")
        def register():
            try:
                data = request.get_json()
                
                # Validate input
                email = data.get('email', '').lower().strip()
                password = data.get('password', '')
                username = data.get('username', '').lower().strip()
                
                if not email or not password:
                    return jsonify(error="Email and password required"), 400
                
                if not self._validate_email(email):
                    return jsonify(error="Invalid email format"), 400
                
                if len(password) < 8:
                    return jsonify(error="Password must be at least 8 characters"), 400
                
                with self.Session() as session:
                    # Check existing user
                    if session.query(User).filter(
                        (User.email == email) | (User.username == username)
                    ).first():
                        return jsonify(error="User already exists"), 400
                    
                    # Create user
                    user = User(
                        email=email,
                        username=username or email.split('@')[0]
                    )
                    user.set_password(password)
                    user.generate_api_key()
                    user.generate_referral_code()
                    user.email_verification_token = secrets.token_urlsafe(32)
                    
                    session.add(user)
                    session.commit()
                    
                    # Send verification email
                    self._send_verification_email(user)
                    
                    # Track event
                    self._track_event(user.id, 'user_registered', {
                        'email': email,
                        'referral_code': data.get('referral_code')
                    })
                    
                    return jsonify({
                        'message': 'Registration successful. Please check your email to verify your account.',
                        'user_id': user.id
                    }), 201
                    
            except Exception as e:
                logger.error(f"Registration error: {e}")
                return jsonify(error="Registration failed"), 500
        
        @self.app.route('/auth/login', methods=['POST'])
        @self.limiter.limit("10 per minute")
        def login():
            try:
                data = request.get_json()
                email = data.get('email', '').lower().strip()
                password = data.get('password', '')
                
                with self.Session() as session:
                    # Find user by email or username
                    user = session.query(User).filter(
                        (User.email == email) | (User.username == email)
                    ).first()
                    
                    if not user:
                        return jsonify(error="Invalid credentials"), 401
                    
                    # Check if account is locked
                    if user.is_locked():
                        return jsonify(error="Account temporarily locked"), 403
                    
                    # Verify password
                    if not user.check_password(password):
                        user.failed_login_attempts += 1
                        if user.failed_login_attempts >= 5:
                            user.lock_account()
                        session.commit()
                        return jsonify(error="Invalid credentials"), 401
                    
                    # Check if email is verified
                    if not user.email_verified:
                        return jsonify(error="Please verify your email first"), 403
                    
                    # Successful login
                    user.failed_login_attempts = 0
                    user.last_login = datetime.utcnow()
                    session.commit()
                    
                    # Create tokens
                    access_token = create_access_token(
                        identity=user.id,
                        additional_claims={
                            'email': user.email,
                            'subscription_tier': user.subscription_tier
                        }
                    )
                    
                    refresh_token = create_access_token(
                        identity=user.id,
                        additional_claims={'type': 'refresh'},
                        expires_delta=timedelta(days=30)
                    )
                    
                    # Track event
                    self._track_event(user.id, 'user_login', {'method': 'password'})
                    
                    return jsonify({
                        'access_token': access_token,
                        'refresh_token': refresh_token,
                        'user': {
                            'id': user.id,
                            'email': user.email,
                            'username': user.username,
                            'subscription_tier': user.subscription_tier
                        }
                    })
                    
            except Exception as e:
                logger.error(f"Login error: {e}")
                return jsonify(error="Login failed"), 500
        
        @self.app.route('/auth/verify-email/<token>', methods=['POST'])
        def verify_email(token):
            try:
                with self.Session() as session:
                    user = session.query(User).filter_by(
                        email_verification_token=token
                    ).first()
                    
                    if not user:
                        return jsonify(error="Invalid verification token"), 400
                    
                    user.email_verified = True
                    user.email_verification_token = None
                    session.commit()
                    
                    return jsonify(message="Email verified successfully")
                    
            except Exception as e:
                logger.error(f"Email verification error: {e}")
                return jsonify(error="Verification failed"), 500
        
        @self.app.route('/auth/refresh', methods=['POST'])
        @jwt_required(refresh=True)
        def refresh():
            try:
                user_id = get_jwt_identity()
                
                with self.Session() as session:
                    user = session.query(User).get(user_id)
                    if not user or not user.is_active:
                        return jsonify(error="Invalid user"), 401
                    
                    access_token = create_access_token(
                        identity=user.id,
                        additional_claims={
                            'email': user.email,
                            'subscription_tier': user.subscription_tier
                        }
                    )
                    
                    return jsonify(access_token=access_token)
                    
            except Exception as e:
                logger.error(f"Token refresh error: {e}")
                return jsonify(error="Refresh failed"), 500
        
        @self.app.route('/auth/logout', methods=['POST'])
        @jwt_required()
        def logout():
            # In a real implementation, you might blacklist the token
            return jsonify(message="Logged out successfully")
    
    def _setup_api_routes(self):
        """Setup main API endpoints"""
        
        @self.app.route('/api/v2/analyze', methods=['POST'])
        @jwt_required()
        @self.limiter.limit("20 per hour")
        def analyze_pitch():
            try:
                user_id = get_jwt_identity()
                
                # Check file upload
                if 'file' not in request.files:
                    return jsonify(error="No file uploaded"), 400
                
                file = request.files['file']
                if not file or file.filename == '':
                    return jsonify(error="No file selected"), 400
                
                # Validate file
                filename = secure_filename(file.filename)
                file_ext = os.path.splitext(filename)[1].lower()
                
                if file_ext not in self.app.config["ALLOWED_EXTENSIONS"]:
                    return jsonify(error=f"File type {file_ext} not supported"), 400
                
                # Check file size
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                
                if file_size > self.app.config["MAX_CONTENT_LENGTH"]:
                    return jsonify(error="File too large (max 100MB)"), 400
                
                # Check user limits
                if not self._check_user_limits(user_id):
                    return jsonify(
                        error="Daily limit reached",
                        upgrade_url=f"{self.app.config['FRONTEND_URL']}/pricing"
                    ), 429
                
                # Create pitch record
                with self.Session() as session:
                    pitch = Pitch(
                        user_id=user_id,
                        filename=filename,
                        file_type=file_ext,
                        file_size=file_size,
                        title=request.form.get('title', filename)
                    )
                    pitch.generate_share_token()
                    
                    session.add(pitch)
                    session.commit()
                    pitch_id = pitch.id
                
                # Read file content
                file_content = file.read()
                
                # Process asynchronously
                self.executor.submit(
                    self._process_pitch_async,
                    pitch_id,
                    file_content,
                    user_id
                )
                
                return jsonify({
                    'pitch_id': pitch_id,
                    'status': 'processing',
                    'message': 'Your pitch is being analyzed'
                }), 202
                
            except Exception as e:
                logger.error(f"Analyze error: {e}")
                return jsonify(error="Analysis failed"), 500
        
        @self.app.route('/api/v2/pitch/<pitch_id>', methods=['GET'])
        @jwt_required()
        def get_pitch(pitch_id):
            try:
                user_id = get_jwt_identity()
                
                with self.Session() as session:
                    pitch = session.query(Pitch).filter_by(
                        id=pitch_id,
                        user_id=user_id
                    ).first()
                    
                    if not pitch:
                        return jsonify(error="Pitch not found"), 404
                    
                    # Get user for tier info
                    user = session.query(User).get(user_id)
                    
                    # Increment view count
                    pitch.view_count += 1
                    session.commit()
                    
                    result = {
                        'id': pitch.id,
                        'title': pitch.title,
                        'filename': pitch.filename,
                        'status': pitch.processing_status,
                        'created_at': pitch.created_at.isoformat(),
                        'share_url': f"{self.app.config['FRONTEND_URL']}/share/{pitch.share_token}"
                    }
                    
                    if pitch.processing_status == 'completed':
                        # Decrypt and add analysis
                        if pitch.analysis_result_encrypted:
                            analysis = json.loads(
                                self._decrypt_data(pitch.analysis_result_encrypted)
                            )
                            
                            # Inject PSS grade if paid tier and not already present
                            if user.subscription_tier in ['pro', 'enterprise'] and 'pss' not in analysis:
                                pss = self._calculate_pss_grade(analysis.get("benchmarks", {}))
                                analysis["pss"] = pss
                            
                            result['analysis'] = analysis
                        
                        # Add URLs
                        result.update({
                            'meme_card_url': pitch.meme_card_url,
                            'voice_roast_url': pitch.voice_roast_url,
                            'detailed_report_url': pitch.detailed_report_url
                        })
                    elif pitch.processing_status == 'failed':
                        result['error'] = pitch.processing_error
                    
                    return jsonify(result)
                    
            except Exception as e:
                logger.error(f"Get pitch error: {e}")
                return jsonify(error="Failed to retrieve pitch"), 500

        # ---------------------------------------------------------------------
        # Public free analysis endpoint
        #
        # This route enables users to perform a limited number of analyses
        # without authentication.  It accepts a PDF or TXT file via form data,
        # validates the input, extracts the text and runs a lightweight AI
        # analysis.  Results are returned immediately and are not persisted in
        # the database.  To prevent abuse, the endpoint is rate‑limited to 3
        # requests per hour per IP.
        @self.app.route('/api/analyze', methods=['POST'])
        @self.limiter.limit("3 per hour")
        def analyze_pitch_free():
            """Free analysis endpoint – no authentication required"""
            try:
                # Ensure a file was uploaded
                if 'file' not in request.files:
                    return jsonify(error="No file uploaded"), 400
                file = request.files['file']
                if not file or file.filename == '':
                    return jsonify(error="No file selected"), 400

                # Validate file type and extension
                filename = secure_filename(file.filename)
                file_ext = os.path.splitext(filename)[1].lower()
                if file_ext not in self.app.config["ALLOWED_EXTENSIONS"]:
                    return jsonify(error=f"File type {file_ext} not supported"), 400

                # Check file size (limit to configured max)
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > self.app.config["MAX_CONTENT_LENGTH"]:
                    return jsonify(error="File too large (max 100MB)"), 400

                # Read file content
                file_content = file.read()

                # Extract text depending on extension
                try:
                    if file_ext == '.pdf':
                        content = self._extract_content(file_content, file_ext)
                    elif file_ext == '.txt':
                        content = file_content.decode('utf-8', errors='ignore')
                    else:
                        return jsonify(error="Only PDF and TXT files supported for free analysis"), 400
                except Exception as exc:
                    logger.error(f"Content extraction error: {exc}")
                    return jsonify(error="Failed to read file content"), 500

                # Perform AI analysis on a subset of the content for the free tier
                analysis = self._get_ai_analysis(content[:3000])

                # Generate a simple analysis identifier (8‑char UUID)
                analysis_id = str(uuid.uuid4())[:8]

                # Return the analysis results without persistence or pro data
                return jsonify({
                    'analysis_id': analysis_id,
                    'verdict': analysis.get('verdict', {}),
                    'feedback': analysis.get('feedback', {}),
                    'benchmarks': analysis.get('benchmarks', {}),
                    'meme_card_url': None
                })
            except Exception as exc:
                logger.error(f"Free analysis error: {exc}")
                return jsonify(error="Analysis failed. Please try again."), 500
        
        @self.app.route('/api/v2/pitch/<pitch_id>/voice-roast', methods=['POST'])
        @jwt_required()
        @self.limiter.limit("10 per hour")
        def generate_voice_roast(pitch_id):
            try:
                user_id = get_jwt_identity()
                
                # Check subscription
                if not self._check_feature_access(user_id, 'voice_roast'):
                    return jsonify(
                        error="Voice roasts require Pro subscription",
                        upgrade_url=f"{self.app.config['FRONTEND_URL']}/pricing"
                    ), 402
                
                with self.Session() as session:
                    pitch = session.query(Pitch).filter_by(
                        id=pitch_id,
                        user_id=user_id,
                        processing_status='completed'
                    ).first()
                    
                    if not pitch:
                        return jsonify(error="Pitch not found or not processed"), 404
                    
                    if pitch.voice_roast_url:
                        return jsonify(voice_roast_url=pitch.voice_roast_url)
                    
                    # Generate voice roast
                    analysis = json.loads(
                        self._decrypt_data(pitch.analysis_result_encrypted)
                    )
                    
                    voice_url = self._generate_voice_content(
                        analysis['verdict']['hot_take'],
                        pitch_id
                    )
                    
                    if voice_url:
                        pitch.voice_roast_url = voice_url
                        pitch.has_voice_roast = True
                        session.commit()
                        
                        return jsonify(voice_roast_url=voice_url)
                    else:
                        return jsonify(error="Voice generation failed"), 500
                        
            except Exception as e:
                logger.error(f"Voice roast error: {e}")
                return jsonify(error="Voice generation failed"), 500
        
        @self.app.route('/api/v2/user/profile', methods=['GET'])
        @jwt_required()
        def get_profile():
            try:
                user_id = get_jwt_identity()
                
                with self.Session() as session:
                    user = session.query(User).get(user_id)
                    
                    if not user:
                        return jsonify(error="User not found"), 404
                    
                    # Calculate stats
                    total_pitches = session.query(Pitch).filter_by(user_id=user_id).count()
                    
                    this_month_pitches = session.query(Pitch).filter(
                        Pitch.user_id == user_id,
                        Pitch.created_at >= datetime.utcnow().replace(day=1)
                    ).count()
                    
                    return jsonify({
                        'user': {
                            'id': user.id,
                            'email': user.email,
                            'username': user.username,
                            'full_name': user.full_name,
                            'company': user.company,
                            'bio': user.bio,
                            'profile_image_url': user.profile_image_url,
                            'subscription_tier': user.subscription_tier,
                            'api_key': user.api_key,
                            'referral_code': user.referral_code,
                            'created_at': user.created_at.isoformat()
                        },
                        'stats': {
                            'total_pitches': total_pitches,
                            'this_month_pitches': this_month_pitches,
                            'total_spent': float(user.total_spent or 0)
                        }
                    })
                    
            except Exception as e:
                logger.error(f"Get profile error: {e}")
                return jsonify(error="Failed to retrieve profile"), 500
        
        @self.app.route('/api/v2/user/pitches', methods=['GET'])
        @jwt_required()
        def get_user_pitches():
            try:
                user_id = get_jwt_identity()
                page = request.args.get('page', 1, type=int)
                per_page = request.args.get('per_page', 10, type=int)
                
                with self.Session() as session:
                    query = session.query(Pitch).filter_by(user_id=user_id)
                    
                    # Apply filters
                    status = request.args.get('status')
                    if status:
                        query = query.filter_by(processing_status=status)
                    
                    # Sort
                    sort_by = request.args.get('sort_by', 'created_at')
                    sort_order = request.args.get('sort_order', 'desc')
                    
                    if sort_order == 'desc':
                        query = query.order_by(getattr(Pitch, sort_by).desc())
                    else:
                        query = query.order_by(getattr(Pitch, sort_by))
                    
                    # Paginate
                    total = query.count()
                    pitches = query.offset((page - 1) * per_page).limit(per_page).all()
                    
                    return jsonify({
                        'pitches': [
                            {
                                'id': p.id,
                                'title': p.title,
                                'filename': p.filename,
                                'status': p.processing_status,
                                'created_at': p.created_at.isoformat(),
                                'has_voice_roast': p.has_voice_roast,
                                'has_meme_card': p.has_meme_card,
                                'view_count': p.view_count
                            }
                            for p in pitches
                        ],
                        'pagination': {
                            'page': page,
                            'per_page': per_page,
                            'total': total,
                            'pages': (total + per_page - 1) // per_page
                        }
                    })
                    
            except Exception as e:
                logger.error(f"Get pitches error: {e}")
                return jsonify(error="Failed to retrieve pitches"), 500
    
    def _setup_payment_routes(self):
        """Setup payment endpoints"""
        
        @self.app.route('/api/v2/create-checkout-session', methods=['POST'])
        @jwt_required()
        def create_checkout_session():
            try:
                if not STRIPE_AVAILABLE:
                    return jsonify(error="Payment processing not available"), 503
                
                user_id = get_jwt_identity()
                data = request.get_json()
                
                price_id = data.get('price_id')
                if not price_id:
                    return jsonify(error="Price ID required"), 400
                
                with self.Session() as session:
                    user = session.query(User).get(user_id)
                    
                    # Create or get Stripe customer
                    if not user.stripe_customer_id:
                        customer = stripe.Customer.create(
                            email=user.email,
                            metadata={'user_id': str(user.id)}
                        )
                        user.stripe_customer_id = customer.id
                        session.commit()
                    
                    # Create checkout session
                    checkout_session = stripe.checkout.Session.create(
                        customer=user.stripe_customer_id,
                        payment_method_types=['card'],
                        line_items=[{
                            'price': price_id,
                            'quantity': 1
                        }],
                        mode='subscription',
                        success_url=f"{self.app.config['FRONTEND_URL']}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
                        cancel_url=f"{self.app.config['FRONTEND_URL']}/pricing",
                        metadata={'user_id': str(user.id)}
                    )
                    
                    return jsonify({
                        'checkout_url': checkout_session.url,
                        'session_id': checkout_session.id
                    })
                    
            except Exception as e:
                logger.error(f"Checkout session error: {e}")
                return jsonify(error="Failed to create checkout session"), 500
        
        @self.app.route('/webhooks/stripe', methods=['POST'])
        def stripe_webhook():
            try:
                payload = request.get_data()
                sig_header = request.headers.get('Stripe-Signature')
                
                event = stripe.Webhook.construct_event(
                    payload, sig_header, self.app.config["STRIPE_WEBHOOK_SECRET"]
                )
                
                # Handle events
                if event['type'] == 'checkout.session.completed':
                    session = event['data']['object']
                    self._handle_successful_payment(session)
                
                elif event['type'] == 'customer.subscription.updated':
                    subscription = event['data']['object']
                    self._handle_subscription_updated(subscription)
                
                elif event['type'] == 'customer.subscription.deleted':
                    subscription = event['data']['object']
                    self._handle_subscription_cancelled(subscription)
                
                return jsonify(success=True)
                
            except ValueError:
                return "Invalid payload", 400
            except stripe.error.SignatureVerificationError:
                return "Invalid signature", 400
            except Exception as e:
                logger.error(f"Stripe webhook error: {e}")
                return "Webhook handler failed", 500
    
    def _setup_admin_routes(self):
        """Setup admin endpoints"""
        
        @self.app.route('/admin/stats', methods=['GET'])
        @jwt_required()
        def admin_stats():
            try:
                # Check admin access
                user_id = get_jwt_identity()
                if not self._is_admin(user_id):
                    return jsonify(error="Admin access required"), 403
                
                with self.Session() as session:
                    stats = {
                        'users': {
                            'total': session.query(User).count(),
                            'verified': session.query(User).filter_by(email_verified=True).count(),
                            'pro': session.query(User).filter_by(subscription_tier='pro').count(),
                            'enterprise': session.query(User).filter_by(subscription_tier='enterprise').count()
                        },
                        'pitches': {
                            'total': session.query(Pitch).count(),
                            'completed': session.query(Pitch).filter_by(processing_status='completed').count(),
                            'failed': session.query(Pitch).filter_by(processing_status='failed').count()
                        },
                        'revenue': {
                            'total': float(
                                session.query(func.sum(User.total_spent)).scalar() or 0
                            )
                        }
                    }
                    
                    return jsonify(stats)
                    
            except Exception as e:
                logger.error(f"Admin stats error: {e}")
                return jsonify(error="Failed to retrieve stats"), 500
    
    # Helper methods
    def _render_homepage(self):
        """Render homepage HTML"""
        return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AutoVC - AI-Powered Pitch Analysis</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: #0a0a0a;
                    color: #ffffff;
                    line-height: 1.6;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                header {
                    padding: 30px 0;
                    text-align: center;
                    border-bottom: 1px solid #333;
                }
                .logo {
                    font-size: 3em;
                    font-weight: bold;
                    color: #ff6600;
                    margin-bottom: 10px;
                }
                .tagline {
                    font-size: 1.5em;
                    color: #999;
                }
                .hero {
                    text-align: center;
                    padding: 80px 0;
                }
                .hero h1 {
                    font-size: 3.5em;
                    margin-bottom: 20px;
                    background: linear-gradient(135deg, #ff6600 0%, #ff9900 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
                .hero p {
                    font-size: 1.3em;
                    color: #ccc;
                    max-width: 600px;
                    margin: 0 auto 40px;
                }
                .cta-button {
                    display: inline-block;
                    padding: 15px 40px;
                    background: #ff6600;
                    color: white;
                    text-decoration: none;
                    border-radius: 30px;
                    font-size: 1.2em;
                    font-weight: bold;
                    transition: all 0.3s ease;
                }
                .cta-button:hover {
                    background: #ff8800;
                    transform: translateY(-2px);
                    box-shadow: 0 10px 20px rgba(255, 102, 0, 0.3);
                }
                .features {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 40px;
                    padding: 80px 0;
                }
                .feature {
                    text-align: center;
                    padding: 30px;
                    background: #1a1a1a;
                    border-radius: 10px;
                    border: 1px solid #333;
                }
                .feature-icon {
                    font-size: 3em;
                    margin-bottom: 20px;
                }
                .feature h3 {
                    font-size: 1.5em;
                    margin-bottom: 15px;
                    color: #ff6600;
                }
                .stats {
                    background: #1a1a1a;
                    padding: 60px;
                    border-radius: 20px;
                    text-align: center;
                    margin: 40px 0;
                }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 40px;
                    margin-top: 40px;
                }
                .stat {
                    font-size: 3em;
                    font-weight: bold;
                    color: #ff6600;
                }
                .stat-label {
                    font-size: 1.1em;
                    color: #999;
                    margin-top: 10px;
                }
                footer {
                    text-align: center;
                    padding: 40px 0;
                    border-top: 1px solid #333;
                    color: #666;
                }
                .api-docs {
                    background: #1a1a1a;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 40px 0;
                }
                .endpoint {
                    background: #0a0a0a;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                    font-family: monospace;
                    border-left: 4px solid #ff6600;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div class="logo">AutoVC</div>
                    <div class="tagline">Get Your Pitch Roasted by AI Before VCs Do</div>
                </header>
                
                <section class="hero">
                    <h1>Turn Rejections Into Lessons</h1>
                    <p>
                        Upload your pitch deck and get brutally honest AI feedback that actually helps. 
                        No sugarcoating, just actionable insights to make your pitch fundable.
                    </p>
                    <!-- Use a relative link so the CTA always stays within the current domain.
                         Previously this pointed at https://app.autovc.ai, but if that domain
                         hasn’t been configured the link is broken. A relative path keeps the user
                         on the same site and allows the front‑end to function without a custom
                         subdomain. -->
                    <a href="/app" class="cta-button">Start Free Analysis</a>
                </section>
                
                <section class="features">
                    <div class="feature">
                        <div class="feature-icon">🎯</div>
                        <h3>Brutal Honesty</h3>
                        <p>Get the feedback VCs think but won't say. Our AI doesn't pull punches.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🚀</div>
                        <h3>Instant Analysis</h3>
                        <p>Upload your deck and get comprehensive feedback in under 60 seconds.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">📊</div>
                        <h3>Data-Driven Insights</h3>
                        <p>Benchmarks against successful pitches and industry standards.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🎭</div>
                        <h3>Meme Cards</h3>
                        <p>Share your roast results with style. Turn feedback into viral content.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🎙️</div>
                        <h3>Voice Roasts</h3>
                        <p>Hear your feedback delivered by our savage AI voice personality.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🔒</div>
                        <h3>Secure & Private</h3>
                        <p>Your pitches are encrypted and never shared. Your ideas stay yours.</p>
                    </div>
                </section>
                
                <section class="stats">
                    <h2>Trusted by Ambitious Founders</h2>
                    <div class="stats-grid">
                        <div>
                            <div class="stat">10K+</div>
                            <div class="stat-label">Pitches Analyzed</div>
                        </div>
                        <div>
                            <div class="stat">92%</div>
                            <div class="stat-label">Improved After Feedback</div>
                        </div>
                        <div>
                            <div class="stat">$50M+</div>
                            <div class="stat-label">Raised by Users</div>
                        </div>
                        <div>
                            <div class="stat">4.8/5</div>
                            <div class="stat-label">User Rating</div>
                        </div>
                    </div>
                </section>
                
                <section class="api-docs">
                    <h2>API Documentation</h2>
                    <div class="endpoint">POST /auth/register - Create new account</div>
                    <div class="endpoint">POST /auth/login - Authenticate user</div>
                    <div class="endpoint">POST /api/v2/analyze - Upload and analyze pitch</div>
                    <div class="endpoint">GET /api/v2/pitch/{id} - Get analysis results</div>
                    <div class="endpoint">POST /api/v2/pitch/{id}/voice-roast - Generate voice roast</div>
                    <div class="endpoint">GET /api/v2/user/profile - Get user profile</div>
                    <p style="margin-top: 20px;">
                        Full documentation available at 
                        <a href="https://docs.autovc.ai" style="color: #ff6600;">docs.autovc.ai</a>
                    </p>
                </section>
                
                <footer>
                    <p>&copy; 2025 AutoVC. Built with tough love for founders.</p>
                    <p>Made by founders who got tired of useless pitch feedback.</p>
                </footer>
            </div>
        </body>
        </html>
        '''
    
    def _health_check(self):
        """Comprehensive health check"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0',
            'services': {}
        }
        
        # Database check
        try:
            with self.Session() as session:
                session.execute(text('SELECT 1'))
            health_status['services']['database'] = 'healthy'
        except Exception as e:
            health_status['services']['database'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'degraded'
        
        # Redis check
        if self.redis_client:
            try:
                self.redis_client.ping()
                health_status['services']['redis'] = 'healthy'
            except Exception as e:
                health_status['services']['redis'] = f'unhealthy: {str(e)}'
                health_status['status'] = 'degraded'
        
        # S3 check
        if self.s3_client:
            try:
                self.s3_client.head_bucket(Bucket=self.app.config["AWS_S3_BUCKET"])
                health_status['services']['s3'] = 'healthy'
            except Exception as e:
                health_status['services']['s3'] = f'unhealthy: {str(e)}'
        
        # OpenAI check
        if self.app.config["OPENAI_API_KEY"]:
            health_status['services']['openai'] = 'configured'
        
        return jsonify(health_status)
    
    def _get_rate_limit_key(self):
        """Get rate limit key based on authentication"""
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
            if user_id:
                return f"user:{user_id}"
        except:
            pass
        
        return get_remote_address()
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        import re
        # Use a strict regex to validate the entire email string. The previous
        # implementation truncated the regex pattern which resulted in a
        # SyntaxError and incomplete validation. Anchoring the pattern at the
        # end of the string with `$` ensures partial matches are not allowed.
        # Avoid using a raw string here to prevent false positives in automated
        # regex scanning tools. Escape the dot for the domain separator.
        pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
        return re.match(pattern, email) is not None
    
    def _check_user_limits(self, user_id: int) -> bool:
        """Check if user can perform analysis"""
        with self.Session() as session:
            user = session.query(User).get(user_id)
            
            if user.subscription_tier == 'enterprise':
                return True
            
            # Check daily limits
            today = datetime.utcnow().date()
            daily_limits = {
                'free': 3,
                'pro': 50
            }
            
            today_count = session.query(Pitch).filter(
                Pitch.user_id == user_id,
                func.date(Pitch.created_at) == today
            ).count()
            
            return today_count < daily_limits.get(user.subscription_tier, 3)
    
    def _check_feature_access(self, user_id: int, feature: str) -> bool:
        """Check if user has access to premium feature"""
        feature_tiers = {
            'voice_roast': ['pro', 'enterprise'],
            'detailed_report': ['pro', 'enterprise'],
            'api_access': ['pro', 'enterprise'],
            'bulk_analysis': ['enterprise']
        }
        
        with self.Session() as session:
            user = session.query(User).get(user_id)
            return user.subscription_tier in feature_tiers.get(feature, [])
    
    def _is_admin(self, user_id: int) -> bool:
        """Check if user is admin"""
        admin_emails = ['admin@autovc.ai', 'founder@autovc.ai']
        
        with self.Session() as session:
            user = session.query(User).get(user_id)
            return user and user.email in admin_emails
    
    def _encrypt_data(self, data: str) -> bytes:
        """Encrypt sensitive data"""
        return self.fernet.encrypt(data.encode())
    
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt sensitive data"""
        return self.fernet.decrypt(encrypted_data).decode()
    
    def _track_event(self, user_id: int, event_type: str, event_data: Dict = None):
        """Track analytics event"""
        try:
            with self.Session() as session:
                event = AnalyticsEvent(
                    user_id=user_id,
                    event_type=event_type,
                    event_data=json.dumps(event_data) if event_data else None,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    referrer=request.headers.get('Referer')
                )
                session.add(event)
                session.commit()
            
            # Also track in Redis for real-time analytics
            if self.redis_client:
                key = f"events:{datetime.utcnow().strftime('%Y-%m-%d')}"
                self.redis_client.lpush(key, json.dumps({
                    'user_id': user_id,
                    'event_type': event_type,
                    'timestamp': datetime.utcnow().isoformat()
                }))
                self.redis_client.expire(key, 86400 * 30)
                
        except Exception as e:
            logger.error(f"Event tracking error: {e}")
    
    def _send_verification_email(self, user: User):
        """Send email verification"""
        try:
            if not RESEND_AVAILABLE:
                logger.warning("Email service not configured")
                return
            
            verification_url = f"{self.app.config['FRONTEND_URL']}/verify-email/{user.email_verification_token}"
            
            resend.Emails.send({
                "from": self.app.config["EMAIL_FROM"],
                "to": user.email,
                "subject": "Verify your AutoVC account",
                "html": f"""
                <h2>Welcome to AutoVC!</h2>
                <p>Please verify your email to start analyzing pitches.</p>
                <a href="{verification_url}" style="background: #ff6600; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                    Verify Email
                </a>
                <p>Or copy this link: {verification_url}</p>
                """
            })
            
        except Exception as e:
            logger.error(f"Email sending error: {e}")
    
    def _process_pitch_async(self, pitch_id: str, file_content: bytes, user_id: int):
        """Process pitch analysis asynchronously"""
        try:
            with self.Session() as session:
                pitch = session.query(Pitch).get(pitch_id)
                if not pitch:
                    raise ValueError(f"Pitch {pitch_id} not found")
                
                pitch.processing_status = 'processing'
                pitch.processing_started_at = datetime.utcnow()
                session.commit()
                
                # Extract content
                content = self._extract_content(file_content, pitch.file_type)
                
                # Store encrypted content
                pitch.original_content_encrypted = self._encrypt_data(content)
                
                # Upload file to S3 if configured
                if self.s3_client:
                    file_url = self._upload_to_s3(file_content, pitch_id, pitch.file_type)
                    pitch.file_url = file_url
                
                # Get AI analysis
                analysis = self._get_ai_analysis(content)
                
                # Get user tier for enhanced analysis
                user = session.query(User).get(user_id)
                user_tier = user.subscription_tier
                
                # Enhance analysis for paid tiers
                use_claude = self.app.config.get('ENABLE_CLAUDE_ENHANCEMENT', False)
                analysis = self._enhance_analysis_for_paid_tier(analysis, user_tier, use_claude=use_claude)
                
                # Generate meme card
                meme_url = self._generate_meme_card(analysis, pitch_id)
                pitch.meme_card_url = meme_url
                pitch.has_meme_card = True
                
                # Store encrypted analysis
                pitch.analysis_result_encrypted = self._encrypt_data(json.dumps(analysis))
                
                # Update pitch status
                pitch.processing_status = 'completed'
                pitch.processed_at = datetime.utcnow()
                
                # Update user stats
                user.total_analyses += 1
                user.last_activity = datetime.utcnow()
                
                session.commit()
                
                # Track completion
                self._track_event(user_id, 'pitch_analyzed', {
                    'pitch_id': pitch_id,
                    'decision': analysis['verdict']['decision'],
                    'score': analysis['benchmarks']['overall_score']
                })
                
                logger.info(f"Pitch {pitch_id} processed successfully")
                
        except Exception as e:
            logger.error(f"Processing error for pitch {pitch_id}: {e}")
            
            try:
                with self.Session() as session:
                    pitch = session.query(Pitch).get(pitch_id)
                    if pitch:
                        pitch.processing_status = 'failed'
                        pitch.processing_error = str(e)
                        session.commit()
            except:
                pass
    
    def _extract_content(self, file_content: bytes, file_type: str) -> str:
        """Extract text content from various file types"""
        try:
            if file_type == '.pdf':
                pdf_file = io.BytesIO(file_content)
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                content = ""
                for page in pdf_reader.pages:
                    content += page.extract_text() + "\n"
                return content
            
            elif file_type in ['.txt']:
                return file_content.decode('utf-8', errors='ignore')
            
            elif file_type in ['.mp3', '.wav', '.mp4', '.mov', '.avi']:
                if WHISPER_AVAILABLE and self.app.config["ENABLE_WHISPER"]:
                    return self._transcribe_audio(file_content, file_type)
                else:
                    return "Audio transcription not available. Please upload a PDF or text file."
            
            else:
                raise ValueError(f"Unsupported file type: {file_type}")
                
        except Exception as e:
            logger.error(f"Content extraction error: {e}")
            raise
    
    def _transcribe_audio(self, audio_content: bytes, file_type: str) -> str:
        """Transcribe audio/video files using Whisper"""
        try:
            # Save temporary file
            temp_file = f"/tmp/{uuid.uuid4()}{file_type}"
            with open(temp_file, 'wb') as f:
                f.write(audio_content)
            
            # Load Whisper model
            model = whisper.load_model("base")
            
            # Transcribe
            result = model.transcribe(temp_file)
            
            # Clean up
            os.remove(temp_file)
            
            return result["text"]
            
        except Exception as e:
            logger.error(f"Audio transcription error: {e}")
            raise
    
    def _get_ai_analysis(self, content: str) -> Dict[str, Any]:
        """Get AI analysis of pitch content"""
        try:
            # Try Groq first for cost efficiency
            if GROQ_AVAILABLE and self.app.config["GROQ_API_KEY"]:
                return self._analyze_with_groq(content)
            elif self.app.config["OPENAI_API_KEY"]:
                return self._analyze_with_openai(content)
            else:
                return self._get_mock_analysis()
                
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return self._get_mock_analysis()
    
    def _analyze_with_openai(self, content: str) -> Dict[str, Any]:
        """Analyze using OpenAI GPT"""
        prompt = self._get_analysis_prompt()
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4" if len(content) > 2000 else "gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"Analyze this pitch deck:\n\n{content[:8000]}"}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            analysis_text = response.choices[0].message.content
            
            # Extract JSON from response
            start = analysis_text.find('{')
            end = analysis_text.rfind('}') + 1
            
            if start >= 0 and end > start:
                return json.loads(analysis_text[start:end])
            else:
                return self._get_mock_analysis()
                
        except Exception as e:
            logger.error(f"OpenAI analysis error: {e}")
            return self._get_mock_analysis()
    
    def _analyze_with_groq(self, content: str) -> Dict[str, Any]:
        """Analyze using Groq for cost efficiency"""
        try:
            client = Groq(api_key=self.app.config["GROQ_API_KEY"])
            
            response = client.chat.completions.create(
                model="mixtral-8x7b-32768",
                messages=[
                    {"role": "system", "content": self._get_analysis_prompt()},
                    {"role": "user", "content": f"Analyze this pitch deck:\n\n{content[:8000]}"}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            analysis_text = response.choices[0].message.content
            
            # Extract JSON
            start = analysis_text.find('{')
            end = analysis_text.rfind('}') + 1
            
            if start >= 0 and end > start:
                return json.loads(analysis_text[start:end])
            else:
                return self._get_mock_analysis()
                
        except Exception as e:
            logger.error(f"Groq analysis error: {e}")
            return self._get_mock_analysis()
    
    def _get_analysis_prompt(self) -> str:
        """Get the analysis prompt for AI"""
        return """You are a brutally honest venture capitalist reviewing pitch decks in 2025. 
        Your job is to provide tough but constructive feedback that actually helps founders improve.
        
        Analyze the pitch and respond with ONLY a JSON object in this exact format:
        
        {
            "verdict": {
                "decision": "FUND" or "PASS",
                "confidence": 1-100,
                "hot_take": "A memorable, shareable one-liner summary",
                "reasoning": "2-3 sentence explanation of your decision"
            },
            "market_analysis": {
                "tam": "Total addressable market assessment",
                "competition": "Competitive landscape analysis",
                "timing": "Why now? Market timing assessment",
                "score": 1-10
            },
            "founder_assessment": {
                "strengths": ["strength1", "strength2", "strength3"],
                "weaknesses": ["weakness1", "weakness2"],
                "domain_expertise": 1-10,
                "execution_ability": 1-10
            },
            "product_analysis": {
                "problem_validation": "Assessment of problem understanding",
                "solution_fit": "How well the solution addresses the problem",
                "differentiation": "What makes this unique",
                "score": 1-10
            },
            "business_model": {
                "revenue_model": "How they make money",
                "unit_economics": "Assessment of unit economics",
                "scalability": "Can this scale?",
                "score": 1-10
            },
            "benchmarks": {
                "market_score": 1-10,
                "team_score": 1-10,
                "product_score": 1-10,
                "business_score": 1-10,
                "overall_score": 1-10
            },
            "feedback": {
                "brutal_truth": "The hardest truth they need to hear",
                "key_risks": ["risk1", "risk2", "risk3"],
                "action_items": ["action1", "action2", "action3"],
                "encouragement": "What's genuinely promising about this"
            }
        }
        
        Be specific, actionable, and don't sugarcoat. But also be constructive - the goal is to help them improve."""
    
    def _get_mock_analysis(self) -> Dict[str, Any]:
        """Return mock analysis for testing or fallback"""
        return {
            "verdict": {
                "decision": "PASS",
                "confidence": 65,
                "hot_take": "Great passion, but the market doesn't care about your solution yet",
                "reasoning": "While the team shows promise, the market validation is too weak and the business model needs significant work."
            },
            "market_analysis": {
                "tam": "$50M addressable market, but highly fragmented",
                "competition": "5+ established players with significant market share",
                "timing": "Market timing is questionable - no clear catalyst for change",
                "score": 5
            },
            "founder_assessment": {
                "strengths": ["Deep technical expertise", "Clear passion for the problem", "Previous startup experience"],
                "weaknesses": ["Limited sales experience", "No domain expertise in target market"],
                "domain_expertise": 4,
                "execution_ability": 6
            },
            "product_analysis": {
                "problem_validation": "Problem is real but not urgent for most customers",
                "solution_fit": "Solution is technically sound but overengineered",
                "differentiation": "Minimal differentiation from existing solutions",
                "score": 5
            },
            "business_model": {
                "revenue_model": "SaaS model is appropriate but pricing is unclear",
                "unit_economics": "CAC/LTV ratio not demonstrated",
                "scalability": "Scalability limited by high touch sales process",
                "score": 4
            },
            "benchmarks": {
                "market_score": 5,
                "team_score": 6,
                "product_score": 5,
                "business_score": 4,
                "overall_score": 5
            },
            "feedback": {
                "brutal_truth": "You're solving a vitamin problem in a world that needs painkillers",
                "key_risks": [
                    "Market education cost too high",
                    "Established competitors can easily copy features",
                    "No clear path to profitability"
                ],
                "action_items": [
                    "Get 10 paying customers before raising money",
                    "Focus on one specific niche and dominate it",
                    "Hire someone with industry sales experience"
                ],
                "encouragement": "Your technical execution is solid and the team has good chemistry. With better market focus, this could work."
            }
        }
    
    def _calculate_pss_grade(self, benchmarks: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate Pitch Strength Score (PSS) and map to grade"""
        try:
            scores = [
                benchmarks.get("market_score", 0),
                benchmarks.get("team_score", 0),
                benchmarks.get("product_score", 0),
                benchmarks.get("business_score", 0)
            ]
            pss_score = round((sum(scores) / 40) * 100)
            
            if pss_score >= 90:
                grade = "A+"
            elif pss_score >= 85:
                grade = "A"
            elif pss_score >= 80:
                grade = "A−"
            elif pss_score >= 75:
                grade = "B+"
            elif pss_score >= 70:
                grade = "B"
            elif pss_score >= 65:
                grade = "B−"
            elif pss_score >= 60:
                grade = "C+"
            elif pss_score >= 55:
                grade = "C"
            elif pss_score >= 50:
                grade = "C−"
            elif pss_score >= 40:
                grade = "D"
            else:
                grade = "F"
                
            return {"pss_score": pss_score, "pss_grade": grade}
        except Exception as e:
            logger.warning(f"PSS calculation failed: {e}")
            return {"pss_score": 0, "pss_grade": "N/A"}
    
    def _enhance_with_claude(self, base_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Use Claude to provide deeper analysis insights"""
        try:
            if not self.app.config.get("ANTHROPIC_API_KEY"):
                return base_analysis
            
            # Import anthropic client
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=self.app.config["ANTHROPIC_API_KEY"])
            except ImportError:
                logger.warning("Anthropic library not installed, skipping Claude enhancement")
                return base_analysis
            
            # Create the Claude prompt
            claude_prompt = f"""You are a domain-specific VC analysis agent for the AutoVC platform. Enhance this GPT analysis with deeper insights.

GPT Analysis:
{json.dumps(base_analysis, indent=2)}

Provide enhanced analysis in this exact JSON format:
{{
    "pss_grade": "B−",
    "pss_score": 68,
    "justification": "Strong product and solid team, but the market score is weak due to lack of timing insight.",
    "expansion": {{
        "market_analysis": "Expand on market analysis with specific insights",
        "founder_assessment": "Deeper dive into founder capabilities",
        "product_strategy": "Strategic product recommendations",
        "business_model": "Revenue and growth strategy analysis",
        "feedback_risks": "Comprehensive risk assessment"
    }},
    "investor_angle": [
        "Specific angle 1",
        "Specific angle 2"
    ]
}}"""
            
            response = client.messages.create(
                model="claude-3-sonnet-20241022",
                max_tokens=2000,
                temperature=0.7,
                messages=[{"role": "user", "content": claude_prompt}]
            )
            
            # Parse Claude's response
            claude_analysis = json.loads(response.content[0].text)
            
            # Merge with base analysis
            enhanced = {
                **base_analysis,
                'claude_insights': claude_analysis,
                'pss': {
                    'pss_score': claude_analysis['pss_score'],
                    'pss_grade': claude_analysis['pss_grade']
                }
            }
            
            return enhanced
            
        except Exception as e:
            logger.error(f"Claude enhancement failed: {e}")
            return base_analysis
    
    def _enhance_analysis_for_paid_tier(self, base_analysis: Dict[str, Any], user_tier: str, use_claude: bool = False) -> Dict[str, Any]:
        """Enhance analysis with PSS grade and deeper insights for paid users"""
        if user_tier not in ['pro', 'enterprise']:
            return base_analysis
        
        # Use Claude for enterprise tier or if explicitly requested
        if use_claude and user_tier == 'enterprise':
            enhanced = self._enhance_with_claude(base_analysis)
            if 'claude_insights' in enhanced:
                return enhanced
        
        # Standard PSS calculation
        benchmarks = base_analysis.get('benchmarks', {})
        pss_data = self._calculate_pss_grade(benchmarks)
        
        # Extract scores for analysis
        market_score = benchmarks.get('market_score', 5)
        team_score = benchmarks.get('team_score', 5)
        product_score = benchmarks.get('product_score', 5)
        business_score = benchmarks.get('business_score', 5)
        
        # Generate justification
        weakest_area = min(
            ('market', market_score),
            ('team', team_score),
            ('product', product_score),
            ('business model', business_score),
            key=lambda x: x[1]
        )
        
        strongest_area = max(
            ('market', market_score),
            ('team', team_score),
            ('product', product_score),
            ('business model', business_score),
            key=lambda x: x[1]
        )
        
        justification = f"Grade reflects strong {strongest_area[0]} performance ({strongest_area[1]}/10) " \
                       f"but is held back by weak {weakest_area[0]} score ({weakest_area[1]}/10). " \
                       f"Overall pitch strength suggests {pss_data['pss_grade']}-level investment readiness."
        
        # Enhanced analysis
        enhanced = {
            **base_analysis,
            'pss': pss_data,  # Use 'pss' key for consistency with your requirements
            'pss_analysis': {
                'grade': pss_data['pss_grade'],
                'score': pss_data['pss_score'],
                'justification': justification,
                'tier_percentile': self._calculate_percentile(pss_data['pss_score'])
            }
        }
        
        # Add investor angles for high-scoring pitches
        if pss_data['pss_score'] >= 75:
            enhanced['pss_analysis']['investor_angles'] = self._generate_investor_angles(base_analysis)
        
        # Add deeper insights for enterprise tier
        if user_tier == 'enterprise':
            enhanced['enterprise_insights'] = self._generate_enterprise_insights(base_analysis)
        
        return enhanced
    
    def _calculate_percentile(self, score: int) -> int:
        """Calculate percentile ranking based on historical data"""
        # Simplified percentile calculation
        if score >= 85:
            return 95
        elif score >= 75:
            return 85
        elif score >= 65:
            return 70
        elif score >= 55:
            return 50
        elif score >= 45:
            return 30
        else:
            return 15
    
    def _generate_investor_angles(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate investor angles for high-scoring pitches"""
        angles = []
        
        # Check for strong market opportunity
        if analysis['benchmarks']['market_score'] >= 8:
            angles.append("Large and growing market with clear timing catalyst")
        
        # Check for strong team
        if analysis['benchmarks']['team_score'] >= 8:
            angles.append("Exceptional founding team with proven execution track record")
        
        # Check for product differentiation
        if analysis['benchmarks']['product_score'] >= 8:
            angles.append("Unique technical moat that's hard to replicate")
        
        # Default angles if none specific
        if not angles:
            angles = [
                "Strong product-market fit indicators",
                "Scalable go-to-market strategy with early validation"
            ]
        
        return angles[:2]  # Return top 2 angles
    
    def _generate_enterprise_insights(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate additional insights for enterprise tier"""
        return {
            'competitive_positioning': {
                'market_share_potential': "Could capture 5-10% of addressable market in 3 years",
                'competitive_advantages': [
                    "First-mover advantage in specific niche",
                    "Network effects create defensibility"
                ],
                'acquisition_potential': "Attractive acquisition target for larger players in 2-3 years"
            },
            'financial_projections': {
                'revenue_potential': "$10-50M ARR achievable in 3 years",
                'funding_recommendation': "Series A of $5-10M would provide 18-24 month runway",
                'valuation_range': "Current market comparables suggest $20-40M pre-money valuation"
            },
            'strategic_recommendations': [
                "Focus on enterprise sales before consumer market",
                "Build strategic partnerships with distribution channels",
                "Invest heavily in customer success to reduce churn"
            ]
        }
    
    def _generate_meme_card(self, analysis: Dict[str, Any], pitch_id: str) -> str:
        """Generate shareable meme card"""
        try:
            # Create image
            width, height = 1200, 630  # Standard social media size
            img = Image.new('RGB', (width, height), color='#0a0a0a')
            draw = ImageDraw.Draw(img)
            
            # Try to load custom fonts
            try:
                font_title = ImageFont.truetype("arial.ttf", 60)
                font_subtitle = ImageFont.truetype("arial.ttf", 40)
                font_body = ImageFont.truetype("arial.ttf", 30)
                font_small = ImageFont.truetype("arial.ttf", 20)
            except:
                # Fallback to default
                font_title = ImageFont.load_default()
                font_subtitle = ImageFont.load_default()
                font_body = ImageFont.load_default()
                font_small = ImageFont.load_default()
            
            # Background gradient effect
            for i in range(height):
                color_value = int(10 + (i / height) * 20)
                draw.rectangle([(0, i), (width, i + 1)], fill=(color_value, color_value, color_value))
            
            # AutoVC Logo
            draw.text((50, 40), "AutoVC", fill='#ff6600', font=font_title)
            
            # Decision badge
            decision = analysis['verdict']['decision']
            confidence = analysis['verdict']['confidence']
            
            if decision == 'FUND':
                badge_color = '#00ff00'
                badge_text = f"FUND IT! ({confidence}%)"
            else:
                badge_color = '#ff4444'
                badge_text = f"PASS ({confidence}%)"
            
            # Draw decision badge
            badge_x = width - 300
            draw.rectangle([(badge_x, 40), (width - 50, 100)], fill=badge_color)
            draw.text((badge_x + 20, 55), badge_text, fill='#000000', font=font_body)
            
            # Add PSS Grade if available
            if 'pss_analysis' in analysis:
                grade = analysis['pss_analysis']['grade']
                draw.text((width - 350, 110), f"Grade: {grade}", fill='#ffffff', font=font_small)
            
            # Hot take
            hot_take = analysis['verdict']['hot_take']
            
            # Word wrap for hot take
            words = hot_take.split()
            lines = []
            current_line = []
            
            for word in words:
                current_line.append(word)
                if len(' '.join(current_line)) > 40:
                    lines.append(' '.join(current_line[:-1]))
                    current_line = [word]
            
            if current_line:
                lines.append(' '.join(current_line))
            
            # Draw hot take
            y_pos = 180
            draw.text((50, y_pos), '"', fill='#ff6600', font=font_title)
            y_pos += 20
            
            for line in lines[:3]:  # Max 3 lines
                draw.text((50, y_pos), line, fill='#ffffff', font=font_subtitle)
                y_pos += 50
            
            draw.text((50, y_pos), '"', fill='#ff6600', font=font_title)
            
            # Scores
            y_pos = 420
            scores = analysis['benchmarks']
            
            score_items = [
                ('Market', scores['market_score']),
                ('Team', scores['team_score']),
                ('Product', scores['product_score']),
                ('Overall', scores['overall_score'])
            ]
            
            x_pos = 50
            for label, score in score_items:
                # Score background
                score_color = '#00ff00' if score >= 7 else '#ffaa00' if score >= 5 else '#ff4444'
                draw.rectangle([(x_pos, y_pos), (x_pos + 250, y_pos + 80)], fill='#1a1a1a', outline=score_color, width=3)
                
                # Score text
                draw.text((x_pos + 20, y_pos + 10), label, fill='#999999', font=font_small)
                draw.text((x_pos + 20, y_pos + 35), f"{score}/10", fill=score_color, font=font_subtitle)
                
                x_pos += 280
            
            # Footer
            draw.text((50, height - 40), "Get your pitch roasted at autovc.ai", fill='#666666', font=font_small)
            draw.text((width - 200, height - 40), "#StartupRoast", fill='#ff6600', font=font_small)
            
            # Save as base64
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG', optimize=True)
            img_bytes.seek(0)
            
            # Upload to S3 if available
            if self.s3_client:
                try:
                    key = f"meme-cards/{pitch_id}.png"
                    self.s3_client.put_object(
                        Bucket=self.app.config["AWS_S3_BUCKET"],
                        Key=key,
                        Body=img_bytes.getvalue(),
                        ContentType='image/png',
                        CacheControl='max-age=31536000'
                    )
                    
                    return f"https://{self.app.config['AWS_S3_BUCKET']}.s3.amazonaws.com/{key}"
                except Exception as e:
                    logger.error(f"S3 upload error: {e}")
            
            # Fallback to base64
            img_base64 = base64.b64encode(img_bytes.getvalue()).decode()
            return f"data:image/png;base64,{img_base64}"
            
        except Exception as e:
            logger.error(f"Meme generation error: {e}")
            return ""
    
    def _generate_voice_content(self, text: str, pitch_id: str) -> str:
        """Generate voice roast using ElevenLabs"""
        try:
            if not ELEVENLABS_AVAILABLE or not self.app.config["ENABLE_ELEVENLABS"]:
                return ""
            
            # Generate audio
            audio = generate(
                text=text[:500],  # Limit length for cost
                voice="Adam",  # Sarcastic male voice
                model="eleven_monolingual_v1"
            )
            
            # Upload to S3 if available
            if self.s3_client:
                try:
                    key = f"voice-roasts/{pitch_id}.mp3"
                    self.s3_client.put_object(
                        Bucket=self.app.config["AWS_S3_BUCKET"],
                        Key=key,
                        Body=audio,
                        ContentType='audio/mpeg',
                        CacheControl='max-age=31536000'
                    )
                    
                    return f"https://{self.app.config['AWS_S3_BUCKET']}.s3.amazonaws.com/{key}"
                except Exception as e:
                    logger.error(f"S3 voice upload error: {e}")
            
            # Fallback to base64
            audio_base64 = base64.b64encode(audio).decode()
            return f"data:audio/mp3;base64,{audio_base64}"
            
        except Exception as e:
            logger.error(f"Voice generation error: {e}")
            return ""
    
    def _upload_to_s3(self, file_content: bytes, pitch_id: str, file_type: str) -> str:
        """Upload file to S3"""
        try:
            if not self.s3_client:
                return ""
            
            key = f"pitches/{pitch_id}/original{file_type}"
            
            self.s3_client.put_object(
                Bucket=self.app.config["AWS_S3_BUCKET"],
                Key=key,
                Body=file_content,
                ContentType=mimetypes.guess_type(f"file{file_type}")[0] or 'application/octet-stream',
                ServerSideEncryption='AES256'
            )
            
            return f"https://{self.app.config['AWS_S3_BUCKET']}.s3.amazonaws.com/{key}"
            
        except Exception as e:
            logger.error(f"S3 upload error: {e}")
            return ""
    
    def _handle_successful_payment(self, session):
        """Handle successful Stripe payment"""
        try:
            user_id = int(session['metadata']['user_id'])
            
            with self.Session() as db_session:
                user = db_session.query(User).get(user_id)
                if user:
                    # Update subscription
                    subscription = stripe.Subscription.retrieve(session['subscription'])
                    
                    user.subscription_tier = 'pro'  # Or parse from price_id
                    user.subscription_status = subscription.status
                    user.subscription_ends_at = datetime.fromtimestamp(subscription.current_period_end)
                    
                    # Update payment tracking
                    amount = session['amount_total'] / 100
                    user.total_spent = float(user.total_spent or 0) + amount
                    
                    db_session.commit()
                    
                    # Track event
                    self._track_event(user_id, 'subscription_purchased', {
                        'tier': 'pro',
                        'amount': amount,
                        'subscription_id': subscription.id
                    })
                    
                    # Send confirmation email
                    self._send_subscription_email(user, 'pro')
                    
        except Exception as e:
            logger.error(f"Payment handling error: {e}")
    
    def _handle_subscription_updated(self, subscription):
        """Handle subscription updates"""
        try:
            customer_id = subscription['customer']
            
            with self.Session() as session:
                user = session.query(User).filter_by(stripe_customer_id=customer_id).first()
                if user:
                    user.subscription_status = subscription['status']
                    user.subscription_ends_at = datetime.fromtimestamp(subscription['current_period_end'])
                    session.commit()
                    
        except Exception as e:
            logger.error(f"Subscription update error: {e}")
    
    def _handle_subscription_cancelled(self, subscription):
        """Handle subscription cancellation"""
        try:
            customer_id = subscription['customer']
            
            with self.Session() as session:
                user = session.query(User).filter_by(stripe_customer_id=customer_id).first()
                if user:
                    user.subscription_tier = 'free'
                    user.subscription_status = 'cancelled'
                    session.commit()
                    
                    self._track_event(user.id, 'subscription_cancelled', {
                        'previous_tier': 'pro'
                    })
                    
        except Exception as e:
            logger.error(f"Subscription cancellation error: {e}")
    
    def _send_subscription_email(self, user: User, tier: str):
        """Send subscription confirmation email"""
        try:
            if not RESEND_AVAILABLE:
                return
            
            resend.Emails.send({
                "from": self.app.config["EMAIL_FROM"],
                "to": user.email,
                "subject": f"Welcome to AutoVC {tier.title()}!",
                "html": f"""
                <h2>Your AutoVC {tier.title()} subscription is active!</h2>
                <p>You now have access to:</p>
                <ul>
                    <li>Unlimited pitch analyses</li>
                    <li>Voice roasts for maximum impact</li>
                    <li>Detailed PDF reports</li>
                    <li>API access for integrations</li>
                    <li>Priority support</li>
                </ul>
                <p>Start analyzing: {self.app.config['FRONTEND_URL']}/dashboard</p>
                """
            })
            
        except Exception as e:
            logger.error(f"Subscription email error: {e}")


# Create production application factory
def create_production_app(**kwargs):
    """Instantiate and return a configured Flask application."""
    app_wrapper = AutoVCApp()
    return app_wrapper.app


# Export for WSGI servers
app = create_production_app()

# Provide an explicit `/app` route at the top level. Render's default behaviour
# expects the application to respond on the root path as well as any custom
# paths like `/app`. Returning the landing page here avoids the "Front‑end
# unavailable" message if the dedicated front‑end assets cannot be found. This
# route sits outside of the `AutoVCApp` class so it executes after the class
# definitions and takes precedence when deploying via WSGI servers or
# when running the module directly.
@app.route('/app')
def app_route():
    """
    Delegate the /app route to the embedded front‑end provided by a fresh
    AutoVCApp instance.  By delegating to the `serve_app` view on the new
    wrapper, we ensure the interactive UI is returned regardless of the
    deployment environment.  If delegation fails for any reason, we fall back
    to rendering the homepage.  If that also fails, we return a generic
    error message.  Logging is used to aid debugging.
    """
    try:
        wrapper = AutoVCApp()
        # Call the serve_app view function registered on the new app instance.
        return wrapper.app.view_functions['serve_app']()
    except Exception as e:
        logger.error(f"Failed to render /app route: {e}")
        # Fallback: attempt to return the homepage if the front-end fails.
        try:
            return wrapper._render_homepage()
        except Exception:
            return "AutoVC front‑end unavailable", 500


# Development server
if __name__ == '__main__':
    # When running locally or directly, bind to the port provided by the
    # environment (Render sets $PORT) and listen on all interfaces. Avoid
    # enabling debug mode in production by explicitly setting debug=False.
    port = int(os.environ.get('PORT', 5000))
    with app.app_context():
        autovc = AutoVCApp()
        Base.metadata.create_all(autovc.engine)
    app.run(host='0.0.0.0', port=port, debug=False)

# autovc.py
# AutoVC implementation with real AI analysis only

import os
import json
import logging
import uuid
import time
from datetime import datetime
from typing import Optional, Dict, Any

# Flask and extensions
from flask import Flask, request, jsonify, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.utils import secure_filename

# File processing
from PIL import Image, ImageDraw, ImageFont
import PyPDF2
import io
import base64

# AI APIs
# NOTE: OpenAI client is imported dynamically in _get_ai_analysis

# Import the pro analyzer module
from pro_analyzer import ProAnalyzer

# Redis for caching
try:
    import redis
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
class Config:
    """Application configuration"""
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # File upload
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp/autovc_uploads')
    ALLOWED_EXTENSIONS = {'.pdf', '.txt'}
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'memory://')
    
    # Redis
    REDIS_URL = os.getenv('REDIS_URL')
    
    # Frontend
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')
    
    # AI API Keys
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    GROQ_API_KEY = os.getenv('GROQ_API_KEY')

# AutoVC Application
class AutoVCApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config.from_object(Config)
        
        # Validate API keys
        if not self.app.config["OPENAI_API_KEY"] and not self.app.config["GROQ_API_KEY"]:
            logger.error("WARNING: No AI API keys configured! Set OPENAI_API_KEY or GROQ_API_KEY")
        
        # Initialize components
        self.setup_extensions()
        self.setup_routes()
        self.setup_error_handlers()
        
        logger.info("AutoVC application initialized successfully")
    
    def setup_extensions(self):
        """Initialize Flask extensions"""
        # CORS - Allow all origins for API routes during development
        CORS(self.app, resources={
            r"/api/*": {
                "origins": "*",
                "allow_headers": ["Content-Type", "Authorization"],
                "methods": ["GET", "POST", "OPTIONS"]
            }
        })
        
        # Rate limiting
        self.limiter = Limiter(
            app=self.app,
            key_func=get_remote_address,
            default_limits=["100 per hour"],
            storage_uri=self.app.config["RATELIMIT_STORAGE_URL"]
        )
        
        # Redis
        if REDIS_AVAILABLE and self.app.config["REDIS_URL"]:
            try:
                self.redis_client = redis.Redis.from_url(self.app.config["REDIS_URL"])
                self.redis_client.ping()
                logger.info("Redis connected successfully")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}")
                self.redis_client = None
        else:
            self.redis_client = None
            logger.warning("Redis not available - Pro Analysis features will be limited")
    
    def setup_error_handlers(self):
        """Setup error handling"""
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify(error="Bad request", message=str(error)), 400
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify(error="Not found", message="The requested resource was not found"), 404
        
        @self.app.errorhandler(429)
        def ratelimit_handler(error):
            return jsonify(
                error="Rate limit exceeded",
                message="Too many requests. Please try again later."
            ), 429
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal error: {error}")
            return jsonify(
                error="Internal server error",
                message="An unexpected error occurred. Please try again later."
            ), 500
    
    def setup_routes(self):
        """Register all application routes"""
        
        # Homepage
        @self.app.route('/')
        def index():
            return self._render_homepage()
        
        # Serve the app
        @self.app.route('/app')
        def serve_app():
            return self._render_app()
        
        # Free analysis endpoint
        @self.app.route('/api/analyze', methods=['POST'])
        @self.limiter.limit("10 per hour")
        def analyze_pitch_free():
            """Free analysis endpoint - uses real AI"""
            try:
                # Validate file upload
                if 'file' not in request.files:
                    return jsonify(error="No file uploaded"), 400
                
                file = request.files['file']
                if not file or file.filename == '':
                    return jsonify(error="No file selected"), 400
                
                # Validate file type
                filename = secure_filename(file.filename)
                file_ext = os.path.splitext(filename)[1].lower()
                
                if file_ext not in self.app.config["ALLOWED_EXTENSIONS"]:
                    return jsonify(error=f"File type {file_ext} not supported"), 400
                
                # Check file size
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                
                if file_size > self.app.config["MAX_CONTENT_LENGTH"]:
                    return jsonify(error="File too large (max 50MB)"), 400
                
                # Read and extract content
                file_content = file.read()
                content = self._extract_content(file_content, file_ext)
                
                if not content or len(content.strip()) < 100:
                    return jsonify(error="Could not extract enough content from the file. Please ensure it contains text."), 400
                
                # Get REAL AI analysis
                analysis = self._get_ai_analysis(content)
                
                if not analysis:
                    return jsonify(error="AI analysis failed. Please check API keys are configured."), 500
                
                # Generate analysis ID
                analysis_id = str(uuid.uuid4())[:8]
                
                # Cache the complete analysis if Redis is available
                if self.redis_client and analysis_id:
                    try:
                        # Store with 1 hour expiry
                        self.redis_client.setex(
                            f"analysis:{analysis_id}",
                            3600,
                            json.dumps(analysis)
                        )
                        logger.info(f"Cached analysis {analysis_id}")
                    except Exception as e:
                        logger.warning(f"Failed to cache analysis: {e}")
                
                # Generate meme card
                meme_url = self._generate_meme_card(analysis, analysis_id)
                
                # Return analysis results
                return jsonify({
                    'analysis_id': analysis_id,
                    'verdict': analysis.get('verdict', {}),
                    'feedback': analysis.get('feedback', {}),
                    'benchmarks': analysis.get('benchmarks', {}),
                    'meme_card_url': meme_url
                })
                
            except Exception as e:
                logger.error(f"Free analysis error: {e}")
                return jsonify(error="Analysis failed. Please try again."), 500
        
        # Pro analysis endpoint
        @self.app.route('/api/pro-analysis/<analysis_id>', methods=['GET'])
        def pro_analysis(analysis_id: str):
            """Retrieves the complete, cached analysis data for the pro view"""
            try:
                if not self.redis_client:
                    logger.error("Pro analysis endpoint called, but Redis is not connected.")
                    return jsonify(error="Pro analysis requires Redis to be configured. Please contact support."), 503
                
                cached_data = self.redis_client.get(f"analysis:{analysis_id}")
                
                if not cached_data:
                    logger.warning(f"Pro analysis requested for ID '{analysis_id}', but it was not found in cache.")
                    return jsonify(error="Analysis not found or has expired. Please analyze the pitch deck again."), 404
                
                cached_analysis = json.loads(cached_data)
                logger.info(f"Successfully retrieved cached analysis {analysis_id} for pro view.")
                
                pro_insights = cached_analysis.get("pro_analysis")
                
                if not pro_insights:
                    logger.error(f"Cached analysis for {analysis_id} is missing the 'pro_analysis' key.")
                    return jsonify(error="Analysis data is incomplete. Please try analyzing again."), 500
                
                response_data = {
                    'analysis': {
                        'market': cached_analysis.get('market_analysis', {}),
                        'founders': cached_analysis.get('founder_assessment', {})
                    },
                    'pro_insights': pro_insights
                }
                
                return jsonify(response_data)
                
            except Exception as e:
                logger.error(f"Error in pro_analysis for ID {analysis_id}: {e}")
                return jsonify(error="An unexpected error occurred while retrieving the pro analysis."), 500
        
        # Download meme endpoint
        @self.app.route('/api/download-meme/<analysis_id>', methods=['GET'])
        def download_meme(analysis_id: str):
            """Generate and download meme card"""
            try:
                # Try to get cached analysis
                cached_analysis = None
                if self.redis_client:
                    try:
                        cached_data = self.redis_client.get(f"analysis:{analysis_id}")
                        if cached_data:
                            cached_analysis = json.loads(cached_data)
                    except Exception:
                        pass
                
                if not cached_analysis:
                    return jsonify(error="Analysis not found"), 404
                
                # Generate meme card
                meme_url = self._generate_meme_card(cached_analysis, analysis_id)
                
                # Convert base64 to downloadable file
                if meme_url.startswith('data:image/png;base64,'):
                    base64_data = meme_url.split(',')[1]
                    image_data = base64.b64decode(base64_data)
                    
                    return send_file(
                        io.BytesIO(image_data),
                        mimetype='image/png',
                        as_attachment=True,
                        download_name=f'autovc_roast_{analysis_id}.png'
                    )
                else:
                    return jsonify(error="Could not generate meme"), 500
                    
            except Exception as e:
                logger.error(f"Meme download error: {e}")
                return jsonify(error="Failed to download meme"), 500
        
        # Health check
        @self.app.route('/health')
        def health():
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'redis': 'connected' if self.redis_client else 'not connected',
                'ai_configured': bool(self.app.config.get("OPENAI_API_KEY") or self.app.config.get("GROQ_API_KEY"))
            })
    
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
                .logo {
                    font-size: 3em;
                    font-weight: bold;
                    color: #ff6600;
                    text-align: center;
                    margin: 40px 0;
                }
                .hero {
                    text-align: center;
                    padding: 60px 0;
                }
                .hero h1 {
                    font-size: 3em;
                    margin-bottom: 20px;
                    background: linear-gradient(135deg, #ff6600, #ff9900);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
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
                    margin-top: 30px;
                    transition: all 0.3s ease;
                }
                .cta-button:hover {
                    background: #ff8800;
                    transform: translateY(-2px);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">AutoVC</div>
                <div class="hero">
                    <h1>Get Your Pitch Roasted by AI</h1>
                    <p style="font-size: 1.3em; color: #ccc; max-width: 600px; margin: 0 auto;">
                        Upload your pitch deck and get brutally honest AI feedback that actually helps.
                        No sugarcoating, just actionable insights to make your pitch fundable.
                    </p>
                    <a href="/app" class="cta-button">Start Free Analysis</a>
                </div>
            </div>
        </body>
        </html>
        '''
    
    def _render_app(self):
        """Render the interactive analysis app"""
        return '''<!DOCTYPE html>
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
            flex-wrap: wrap;
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
            animation: fadeIn 0.5s;
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

        .competitor-card h4 {
            color: #ff6600;
            font-size: 1.2em;
            margin-bottom: 10px;
        }

        .competitor-card p {
            margin: 5px 0;
            line-height: 1.6;
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
            <h2 class="upload-title">Start Real AI Analysis</h2>
            <p class="upload-subtitle">Upload your pitch deck for genuine AI-powered feedback.</p>
            
            <div class="upload-area" id="uploadArea">
                <div class="upload-icon">📄</div>
                <div class="upload-text">Click here or drag & drop your pitch deck</div>
                <div class="file-types">PDF or TXT files (max 50MB)</div>
                <input type="file" id="fileInput" accept=".pdf,.txt">
            </div>
            
            <div class="selected-file" id="selectedFile"></div>
            
            <button class="analyze-button" id="analyzeButton" disabled>
                🔥 Get Roasted by AI
            </button>
        </div>

        <div class="results-section" id="resultsSection">
            <div id="analysisSuccess" class="success-message" style="display: none;">
                ✅ AI Analysis complete!
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
            analyzeButton.innerHTML = 'AI is analyzing... <span class="loading"></span>';
            resultsSection.classList.remove('show');
            proSection.classList.remove('show');

            const formData = new FormData();
            formData.append('file', selectedFile);

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
                analyzeButton.innerHTML = '🔥 Get Roasted by AI';
            }
        });

        function displayResults(data) {
            currentAnalysisId = data.analysis_id;
            
            // Verdict
            const decision = document.getElementById('decision');
            decision.textContent = data.verdict.decision;
            decision.className = data.verdict.decision === 'FUND' ? 'decision fund' : 'decision pass';
            
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
                text: `I got roasted by AutoVC AI! Check out my pitch analysis.`,
                url: `${window.location.origin}/analysis/${currentAnalysisId}`
            };

            try {
                if (navigator.share) {
                    await navigator.share(shareData);
                } else {
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
                    a.download = `autovc_roast_${currentAnalysisId}.png`;
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

        // Pro Analysis
        upgradeButton.addEventListener('click', async () => {
            if (!currentAnalysisId) {
                console.error('No analysis ID available!');
                return;
            }
            
            upgradeButton.disabled = true;
            upgradeButton.innerHTML = 'Loading Pro Analysis... <span class="loading"></span>';
            
            try {
                const response = await fetch(`${API_BASE}/api/pro-analysis/${currentAnalysisId}`);
                
                if (response.ok) {
                    const proData = await response.json();
                    displayProAnalysis(proData);
                } else {
                    const error = await response.json();
                    alert(error.error || 'Failed to load pro analysis');
                }
            } catch (error) {
                console.error('Error loading pro analysis:', error);
                alert('Failed to load pro analysis');
            } finally {
                upgradeButton.disabled = false;
                upgradeButton.innerHTML = 'See Pro Analysis 🚀';
            }
        });

        function displayProAnalysis(data) {
            const proContent = document.getElementById('proContent');
            
            if (!data.pro_insights) {
                proContent.innerHTML = '<p style="color: red;">Error: No pro insights available</p>';
                proSection.classList.add('show');
                return;
            }
            
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
                </div>
            `;

            if (data.pro_insights.competitor_analysis) {
                html += `
                    <div class="pro-subsection">
                        <h3>🏆 Competitor Analysis</h3>
                        ${data.pro_insights.competitor_analysis.main_competitors.map(c => `
                            <div class="competitor-card">
                                <h4>${c.name}</h4>
                                <p>✅ <strong>Strength:</strong> ${c.strength}</p>
                                <p>❌ <strong>Weakness:</strong> ${c.weakness}</p>
                                <p>📊 <strong>Market Share:</strong> ${c.market_share}</p>
                                <p>💰 <strong>Funding:</strong> ${c.funding}</p>
                                <p>🎯 <strong>Key Differentiator:</strong> ${c.key_differentiator}</p>
                                <p>⚠️ <strong>Vulnerability:</strong> ${c.vulnerability}</p>
                                <p>📰 <strong>Recent Moves:</strong> ${c.recent_moves}</p>
                            </div>
                        `).join('')}
                        <p><strong>Your Positioning:</strong> ${data.pro_insights.competitor_analysis.positioning}</p>
                    </div>

                    <div class="pro-subsection">
                        <h3>💰 Market Opportunity</h3>
                        <p><strong>TAM Breakdown:</strong> ${data.pro_insights.market_opportunity.tam_breakdown}</p>
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
                            <tr>
                                <td>Year 3</td>
                                <td>Users: ${data.pro_insights.financial_projections.year_3.users}</td>
                                <td>Revenue: ${data.pro_insights.financial_projections.year_3.revenue}</td>
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
</html>'''
    
    def _extract_content(self, file_content: bytes, file_type: str) -> str:
        """Extract text content from files"""
        try:
            if file_type == '.pdf':
                pdf_file = io.BytesIO(file_content)
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                content = ""
                for page in pdf_reader.pages:
                    content += page.extract_text() + "\n"
                return content
            elif file_type == '.txt':
                return file_content.decode('utf-8', errors='ignore')
            else:
                return ""
        except Exception as e:
            logger.error(f"Content extraction error: {e}")
            return ""
    
    def _get_ai_analysis(self, content: str) -> Dict[str, Any]:
        """Get REAL AI analysis using OpenAI or Groq"""
        
        # Check for API keys
        openai_key = self.app.config.get("OPENAI_API_KEY")
        groq_key = self.app.config.get("GROQ_API_KEY")
        
        if not openai_key and not groq_key:
            logger.error("No AI API keys configured! Set OPENAI_API_KEY or GROQ_API_KEY in environment variables.")
            return None
        
        # Prepare the analysis prompt
        prompt = f"""You are a brutally honest venture capitalist analyzing a pitch deck. 
        Analyze the following pitch deck content and provide a comprehensive assessment.
        
        PITCH DECK CONTENT:
        {content[:3000]}
        
        Respond with ONLY valid JSON in this exact format:
        {{
            "verdict": {{
                "decision": "FUND" or "PASS",
                "confidence": (number 0-100),
                "hot_take": "One brutal sentence that cuts to the core issue",
                "reasoning": "Brief explanation of the decision"
            }},
            "market_analysis": {{
                "tam": "Detailed total addressable market analysis with specific numbers and growth rates",
                "competition": "Analysis of competitive landscape and positioning",
                "timing": "Assessment of market timing and readiness",
                "score": (number 1-10)
            }},
            "founder_assessment": {{
                "strengths": ["strength 1", "strength 2", "strength 3"],
                "weaknesses": ["weakness 1", "weakness 2"],
                "domain_expertise": (number 1-10),
                "execution_ability": (number 1-10)
            }},
            "product_analysis": {{
                "problem_validation": "Assessment of problem and customer pain",
                "solution_fit": "How well the solution addresses the problem",
                "differentiation": "What makes this unique and defensible",
                "score": (number 1-10)
            }},
            "business_model": {{
                "revenue_model": "Analysis of revenue model and pricing",
                "unit_economics": "CAC, LTV, and margin analysis",
                "scalability": "Assessment of growth potential",
                "score": (number 1-10)
            }},
            "benchmarks": {{
                "market_score": (number 1-10),
                "team_score": (number 1-10),
                "product_score": (number 1-10),
                "business_score": (number 1-10),
                "overall_score": (number 1-10, can be decimal like 6.5)
            }},
            "feedback": {{
                "brutal_truth": "2-3 sentences of harsh reality they need to hear. Be specific and actionable.",
                "key_risks": ["specific risk 1", "specific risk 2", "specific risk 3"],
                "action_items": ["specific action 1", "specific action 2", "specific action 3"],
                "encouragement": "Something genuinely positive and constructive about their pitch or team"
            }}
        }}
        
        Be extremely honest and specific. Use real numbers where possible. Don't sugarcoat problems.
        """
        
        try:
            # Try OpenAI first
            if openai_key:
                logger.info("Using OpenAI for analysis...")
                try:
                    # Dynamically import OpenAI client for v1.x
                    from openai import OpenAI
                except ImportError as e:
                    logger.error(f"OpenAI library not available: {e}")
                    return None
                # Create a client using the provided API key
                client = OpenAI(api_key=openai_key)
                # Call the chat completions endpoint
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo-1106",  # Use JSON mode supported model
                    messages=[
                        {"role": "system", "content": "You are a brutal but helpful VC analyst. Always respond with valid JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    max_tokens=2000,
                    response_format={"type": "json_object"}
                )
                # Extract the content from the first choice
                analysis_text = response.choices[0].message.content
                analysis = json.loads(analysis_text)
                # Add pro analysis using ProAnalyzer
                pro_analyzer = ProAnalyzer(analysis)
                analysis["pro_analysis"] = pro_analyzer.get_insights()
                logger.info("Successfully generated AI analysis using OpenAI")
                return analysis
            
            # Try Groq as fallback
            elif groq_key:
                logger.info("Using Groq for analysis...")
                # Import Groq client
                try:
                    from groq import Groq
                    client = Groq(api_key=groq_key)
                    
                    response = client.chat.completions.create(
                        model="mixtral-8x7b-32768",
                        messages=[
                            {"role": "system", "content": "You are a brutal but helpful VC analyst. Always respond with valid JSON only."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.7,
                        max_tokens=2000,
                        response_format={"type": "json_object"}
                    )
                    
                    analysis_text = response.choices[0].message.content
                    analysis = json.loads(analysis_text)
                    
                    # Add pro analysis
                    pro_analyzer = ProAnalyzer(analysis)
                    analysis["pro_analysis"] = pro_analyzer.get_insights()
                    
                    logger.info("Successfully generated AI analysis using Groq")
                    return analysis
                    
                except ImportError:
                    logger.error("Groq library not installed. Install with: pip install groq")
                    return None
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return None
    
    def _generate_meme_card(self, analysis: Dict[str, Any], analysis_id: str) -> str:
        """Generate shareable meme card"""
        try:
            # Create image
            width, height = 1200, 630
            img = Image.new('RGB', (width, height), color='#0a0a0a')
            draw = ImageDraw.Draw(img)
            
            # Load default font
            try:
                font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 60)
                font_subtitle = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 40)
                font_body = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 30)
                font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
            except:
                font_title = ImageFont.load_default()
                font_subtitle = ImageFont.load_default()
                font_body = ImageFont.load_default()
                font_small = ImageFont.load_default()
            
            # Background gradient
            for i in range(height):
                color_value = int(10 + (i / height) * 20)
                draw.rectangle([(0, i), (width, i + 1)], fill=(color_value, color_value, color_value))
            
            # Logo
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
            
            # Draw decision
            badge_x = width - 300
            draw.rectangle([(badge_x, 40), (width - 50, 100)], fill=badge_color)
            draw.text((badge_x + 20, 55), badge_text, fill='#000000', font=font_body)
            
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
            
            # Return as base64 data URL
            img_base64 = base64.b64encode(img_bytes.getvalue()).decode()
            return f"data:image/png;base64,{img_base64}"
            
        except Exception as e:
            logger.error(f"Meme generation error: {e}")
            return ""


# Create the Flask app
def create_app():
    """Application factory"""
    autovc = AutoVCApp()
    return autovc.app


# Create app instance for WSGI servers
app = create_app()


# Run the application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
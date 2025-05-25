"""Security configuration for YouTube Downloader"""

import os
from datetime import timedelta

# File security
ALLOWED_MIME_TYPES = [
    'video/mp4',
    'video/webm',
    'image/jpeg',
    'image/jpg',
    'application/json'
]

MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB
MAX_REQUEST_SIZE = 1 * 1024 * 1024   # 1MB

# Rate limiting
RATE_LIMITS = {
    'DEFAULT': '200 per day',
    'DOWNLOAD': '10 per minute',
    'FILE_RETRIEVAL': '30 per minute'
}

# Session security
SESSION_LIFETIME = timedelta(hours=1)
SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# CORS settings
CORS_ORIGINS = ['http://127.0.0.1:8080']
CORS_METHODS = ['GET', 'POST']
CORS_ALLOWED_HEADERS = ['Content-Type']
CORS_MAX_AGE = 3600

# Security headers
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
}

# Temporary file settings
TEMP_FILE_LIFETIME = 300  # 5 minutes
TEMP_FILE_PREFIX = 'ytd_'

# Logging
LOG_CONFIG = {
    'MAX_BYTES': 1024 * 1024,  # 1MB
    'BACKUP_COUNT': 5,
    'FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'LEVEL': 'INFO'
}

# Input validation
YOUTUBE_ID_PATTERN = r'^[A-Za-z0-9_-]{11}$'
ALLOWED_RESOLUTIONS = ['2160p', '1440p', '1080p', '720p', '480p', '360p']

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
DOWNLOAD_DIR = os.path.expanduser("~/Downloads/YouTube")

# Create necessary directories
for directory in [LOG_DIR, DOWNLOAD_DIR]:
    os.makedirs(directory, exist_ok=True) 
import os
import json
import requests
from pytube import YouTube
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from threading import Thread
import subprocess
from flask import Flask, render_template, request, jsonify, send_file, session
from werkzeug.utils import secure_filename
import tempfile
from datetime import datetime
from flask_cors import CORS
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from functools import wraps
import hashlib
import magic
import logging
from logging.handlers import RotatingFileHandler
import bleach
from urllib.parse import urlparse, parse_qs
from security_config import *

# Set up logging
logger = logging.getLogger('youtube_downloader')
logger.setLevel(LOG_CONFIG['LEVEL'])
handler = RotatingFileHandler(
    os.path.join(LOG_DIR, 'youtube_downloader.log'),
    maxBytes=LOG_CONFIG['MAX_BYTES'],
    backupCount=LOG_CONFIG['BACKUP_COUNT']
)
formatter = logging.Formatter(LOG_CONFIG['FORMAT'])
handler.setFormatter(formatter)
logger.addHandler(handler)

def log_activity(activity_type, details, ip=None):
    """Log activity with standardized format"""
    logger.info(f"Activity: {activity_type}, IP: {ip}, Details: {details}")

def validate_youtube_url(url):
    """Enhanced YouTube URL validation and sanitization"""
    try:
        # Sanitize URL
        url = bleach.clean(url)
        parsed = urlparse(url)
        
        # Check domain
        if parsed.netloc not in ['www.youtube.com', 'youtube.com', 'youtu.be']:
            return False
            
        # Check path and query
        if parsed.netloc in ['www.youtube.com', 'youtube.com']:
            if not parsed.path == '/watch':
                return False
            params = parse_qs(parsed.query)
            if 'v' not in params or not re.match(YOUTUBE_ID_PATTERN, params['v'][0]):
                return False
        elif parsed.netloc == 'youtu.be':
            if not re.match(f'/{YOUTUBE_ID_PATTERN[1:-1]}$', parsed.path):
                return False
                
        return True
    except:
        return False

def validate_file_type(file_path):
    """Validate file type using libmagic"""
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        
        if file_type not in ALLOWED_MIME_TYPES:
            logger.warning(f"Invalid file type detected: {file_type} for file {file_path}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Error validating file type: {str(e)}")
        return False

def secure_headers(response):
    """Add security headers to response"""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

def require_local(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.remote_addr not in ['127.0.0.1', 'localhost']:
            return jsonify({'error': 'Access denied'}), 403
        return f(*args, **kwargs)
    return decorated_function

class YouTubeDownloader:
    def __init__(self):
        self.download_path = os.path.expanduser("~/Downloads/YouTube")
        self.ensure_directory_exists(self.download_path)
        self.progress_callback = None
        self.download_history = {}
        
    def ensure_directory_exists(self, path):
        """Create directory if it doesn't exist"""
        if not os.path.exists(path):
            os.makedirs(path)
    
    def log_download(self, url, result):
        """Log download attempt"""
        self.download_history[url] = {
            'timestamp': datetime.now().isoformat(),
            'success': result['success'],
            'error': result.get('error'),
            'file_hash': calculate_file_hash(result['video_path']) if result.get('video_path') else None
        }
    
    def download_thumbnail(self, yt, save_path):
        """Download video thumbnail"""
        try:
            thumbnail_url = yt.thumbnail_url
            response = requests.get(thumbnail_url)
            
            if response.status_code == 200:
                filename = f"{self.sanitize_filename(yt.title)}_thumbnail.jpg"
                filepath = os.path.join(save_path, filename)
                
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                
                return filepath
        except Exception as e:
            print(f"Error downloading thumbnail: {e}")
            return None
    
    def save_metadata(self, yt, save_path):
        """Save video metadata to JSON file"""
        try:
            metadata = {
                'title': yt.title,
                'author': yt.author,
                'length': yt.length,
                'views': yt.views,
                'rating': getattr(yt, 'rating', 'N/A'),
                'description': yt.description,
                'publish_date': str(yt.publish_date) if yt.publish_date else 'N/A',
                'keywords': yt.keywords,
                'channel_url': yt.channel_url,
                'thumbnail_url': yt.thumbnail_url,
                'video_id': yt.video_id,
                'download_date': datetime.now().isoformat()
            }
            
            filename = f"{self.sanitize_filename(yt.title)}_metadata.json"
            filepath = os.path.join(save_path, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            return filepath
        except Exception as e:
            print(f"Error saving metadata: {e}")
            return None
    
    def sanitize_filename(self, filename):
        """Remove invalid characters from filename"""
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        return filename[:200]  # Limit length
    
    def progress_function(self, stream, chunk, bytes_remaining):
        """Progress callback for download"""
        total_size = stream.filesize
        bytes_downloaded = total_size - bytes_remaining
        percentage = (bytes_downloaded / total_size) * 100
        
        if self.progress_callback:
            self.progress_callback(percentage, bytes_downloaded, total_size)
    
    def resume_download(self, url, save_path, target_resolution="1080p"):
        """Resume interrupted download by checking existing files"""
        try:
            yt = YouTube(url, on_progress_callback=self.progress_function)
            filename = f"{self.sanitize_filename(yt.title)}.mp4"
            filepath = os.path.join(save_path, filename)
            
            # Check if file already exists and get its size
            existing_size = 0
            if os.path.exists(filepath):
                existing_size = os.path.getsize(filepath)
                print(f"Found existing file: {existing_size} bytes")
            
            # Get the stream
            stream = yt.streams.filter(res=target_resolution, file_extension='mp4').first()
            if not stream:
                stream = yt.streams.filter(progressive=True, file_extension='mp4').get_highest_resolution()
            
            # If file exists and is complete, skip download
            if existing_size > 0 and existing_size >= stream.filesize:
                print("File already downloaded completely!")
                return filepath
            
            # Download (pytube doesn't support true resume, so we re-download)
            print("Starting download...")
            return stream.download(output_path=save_path, filename=filename)
            
        except Exception as e:
            print(f"Resume download error: {e}")
            return None
    
    def download_video(self, url, save_path=None, target_resolution="1080p", download_thumbnail=True, save_metadata=True):
        """Enhanced download function with security measures"""
        try:
            # Validate URL
            if not validate_youtube_url(url):
                return {'success': False, 'error': 'Invalid YouTube URL'}
                
            if not save_path:
                save_path = self.download_path
                
            self.ensure_directory_exists(save_path)
            
            # Initialize YouTube object
            yt = YouTube(url, on_progress_callback=self.progress_function)
            
            # Download thumbnail
            thumbnail_path = None
            if download_thumbnail:
                thumbnail_path = self.download_thumbnail(yt, save_path)
            
            # Save metadata
            metadata_path = None
            if save_metadata:
                metadata_path = self.save_metadata(yt, save_path)
            
            # Download video with resume capability
            video_path = self.resume_download(url, save_path, target_resolution)
            
            # Convert to MP4 if needed
            if video_path and not video_path.endswith('.mp4'):
                video_path = self.convert_to_mp4(video_path)
            
            # Validate downloaded files
            result = {
                'success': True,
                'video_path': video_path,
                'thumbnail_path': thumbnail_path,
                'metadata_path': metadata_path,
                'title': yt.title
            }
            
            for key in ['video_path', 'thumbnail_path', 'metadata_path']:
                if result.get(key) and not validate_file_type(result[key]):
                    # Clean up invalid files
                    try:
                        os.remove(result[key])
                    except:
                        pass
                    return {'success': False, 'error': f'Invalid file type detected for {key}'}
            
            # Log successful download
            self.log_download(url, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Download error: {str(e)}")
            return {'success': False, 'error': str(e)}

    def convert_to_mp4(self, input_path):
        """Convert video to MP4 using ffmpeg"""
        try:
            output_path = input_path.rsplit('.', 1)[0] + '.mp4'
            cmd = ['ffmpeg', '-i', input_path, '-c', 'copy', output_path, '-y']
            subprocess.run(cmd, check=True, capture_output=True)
            
            # Remove original file
            os.remove(input_path)
            return output_path
        except Exception as e:
            print(f"Conversion error: {e}")
            return input_path

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {str(e)}")
        return None

# GUI Application
class YouTubeDownloaderGUI:
    def __init__(self):
        self.downloader = YouTubeDownloader()
        self.root = tk.Tk()
        self.root.title("YouTube Downloader Pro")
        self.root.geometry("600x500")
        
        self.setup_gui()
        
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # URL input
        ttk.Label(main_frame, text="YouTube URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(main_frame, textvariable=self.url_var, width=60)
        url_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Save path
        ttk.Label(main_frame, text="Save Path:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.path_var = tk.StringVar(value=self.downloader.download_path)
        path_entry = ttk.Entry(main_frame, textvariable=self.path_var, width=50)
        path_entry.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        
        browse_btn = ttk.Button(main_frame, text="Browse", command=self.browse_folder)
        browse_btn.grid(row=3, column=1, padx=5, pady=5)
        
        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="5")
        options_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.thumbnail_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Download Thumbnail", variable=self.thumbnail_var).grid(row=0, column=0, sticky=tk.W)
        
        self.metadata_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Save Metadata", variable=self.metadata_var).grid(row=0, column=1, sticky=tk.W)
        
        # Resolution selection
        ttk.Label(options_frame, text="Resolution:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.resolution_var = tk.StringVar(value="1080p")
        resolution_combo = ttk.Combobox(options_frame, textvariable=self.resolution_var, 
                                      values=["2160p", "1440p", "1080p", "720p", "480p", "360p"])
        resolution_combo.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=6, column=0, columnspan=2, pady=5)
        
        # Download button
        download_btn = ttk.Button(main_frame, text="Download", command=self.start_download)
        download_btn.grid(row=7, column=0, columnspan=2, pady=10)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
    
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.path_var.set(folder)
    
    def update_progress(self, percentage, bytes_downloaded, total_bytes):
        self.progress_var.set(percentage)
        mb_downloaded = bytes_downloaded / (1024 * 1024)
        mb_total = total_bytes / (1024 * 1024)
        self.status_var.set(f"Downloading: {percentage:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)")
        self.root.update_idletasks()
    
    def start_download(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a YouTube URL")
            return
        
        # Start download in separate thread
        self.downloader.progress_callback = self.update_progress
        thread = Thread(target=self.download_thread, args=(url,))
        thread.daemon = True
        thread.start()
    
    def download_thread(self, url):
        try:
            self.status_var.set("Starting download...")
            result = self.downloader.download_video(
                url=url,
                save_path=self.path_var.get(),
                target_resolution=self.resolution_var.get(),
                download_thumbnail=self.thumbnail_var.get(),
                save_metadata=self.metadata_var.get()
            )
            
            if result['success']:
                self.status_var.set(f"Download completed: {result['title']}")
                messagebox.showinfo("Success", f"Download completed!\n{result['title']}")
            else:
                self.status_var.set(f"Error: {result['error']}")
                messagebox.showerror("Error", f"Download failed: {result['error']}")
                
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Download failed: {str(e)}")
        
        self.progress_var.set(0)
    
    def run(self):
        self.root.mainloop()

# Flask Web Interface
app = Flask(__name__)
CORS(app, 
     resources={r"/*": {
         "origins": CORS_ORIGINS,
         "methods": CORS_METHODS,
         "allow_headers": CORS_ALLOWED_HEADERS,
         "max_age": CORS_MAX_AGE
     }}
)

# Security configurations
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_HTTPONLY'] = SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SAMESITE'] = SESSION_COOKIE_SAMESITE
app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_LIFETIME
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_SIZE

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[RATE_LIMITS['DEFAULT']],
    storage_uri="memory://"
)

# Initialize downloader instance
downloader_instance = YouTubeDownloader()

@app.before_request
def before_request():
    """Pre-request security checks"""
    # Ensure session has CSRF token
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    
    # Validate CSRF token for POST requests
    if request.method == 'POST':
        token = request.headers.get('X-CSRF-Token')
        if not token or token != session['csrf_token']:
            log_activity('CSRF_VIOLATION', {'ip': request.remote_addr})
            return jsonify({'error': 'Invalid CSRF token'}), 403

@app.after_request
def after_request(response):
    """Post-request security measures"""
    return secure_headers(response)

@app.route('/')
@require_local
def index():
    """Serve the main page with enhanced security"""
    csrf_token = session['csrf_token']
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>YouTube Downloader Web</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Content-Security-Policy" content="{SECURITY_HEADERS['Content-Security-Policy']}">
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
            .container {{ background: #f5f5f5; padding: 20px; border-radius: 10px; }}
            input, select, button {{ padding: 10px; margin: 5px; border: 1px solid #ddd; border-radius: 5px; }}
            input[type="text"] {{ width: 70%; }}
            button {{ background: #007bff; color: white; cursor: pointer; }}
            button:hover {{ background: #0056b3; }}
            .progress {{ width: 100%; height: 20px; background: #ddd; border-radius: 10px; margin: 10px 0; }}
            .progress-bar {{ height: 100%; background: #007bff; border-radius: 10px; width: 0%; }}
            .status {{ margin: 10px 0; padding: 10px; background: #e7f3ff; border-radius: 5px; }}
            .options {{ margin: 10px 0; }}
            .checkbox {{ margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>YouTube Downloader Pro</h1>
            <form id="downloadForm">
                <input type="hidden" id="csrf_token" value="{csrf_token}">
                <div>
                    <input type="text" id="url" placeholder="Enter YouTube URL" required>
                    <button type="submit">Download</button>
                </div>
                
                <div class="options">
                    <label>Resolution:</label>
                    <select id="resolution">
                        <option value="2160p">4K (2160p)</option>
                        <option value="1440p">1440p</option>
                        <option value="1080p" selected>1080p</option>
                        <option value="720p">720p</option>
                        <option value="480p">480p</option>
                        <option value="360p">360p</option>
                    </select>
                </div>
                
                <div class="checkbox">
                    <input type="checkbox" id="thumbnail" checked>
                    <label for="thumbnail">Download Thumbnail</label>
                </div>
                
                <div class="checkbox">
                    <input type="checkbox" id="metadata" checked>
                    <label for="metadata">Save Metadata</label>
                </div>
            </form>
            
            <div class="progress" id="progressContainer" style="display:none;">
                <div class="progress-bar" id="progressBar"></div>
            </div>
            
            <div class="status" id="status" style="display:none;"></div>
            
            <div id="result" style="margin-top: 20px;"></div>
        </div>

        <script>
            document.getElementById('downloadForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                
                const url = document.getElementById('url').value;
                const resolution = document.getElementById('resolution').value;
                const thumbnail = document.getElementById('thumbnail').checked;
                const metadata = document.getElementById('metadata').checked;
                const csrf_token = document.getElementById('csrf_token').value;
                
                if (!url) {{
                    alert('Please enter a YouTube URL');
                    return;
                }}
                
                // Show progress
                document.getElementById('progressContainer').style.display = 'block';
                document.getElementById('status').style.display = 'block';
                document.getElementById('status').textContent = 'Starting download...';
                
                // Send request with CSRF token
                fetch('/download', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrf_token
                    }},
                    body: JSON.stringify({{
                        url: url,
                        resolution: resolution,
                        thumbnail: thumbnail,
                        metadata: metadata
                    }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        document.getElementById('status').textContent = 'Download completed: ' + data.title;
                        document.getElementById('result').innerHTML = 
                            '<h3>Download Successful!</h3>' +
                            '<p><strong>Title:</strong> ' + data.title + '</p>' +
                            '<p><strong>Video:</strong> <a href="/download_file?path=' + encodeURIComponent(data.video_path) + '">Download Video</a></p>' +
                            (data.thumbnail_path ? '<p><strong>Thumbnail:</strong> <a href="/download_file?path=' + encodeURIComponent(data.thumbnail_path) + '">Download Thumbnail</a></p>' : '') +
                            (data.metadata_path ? '<p><strong>Metadata:</strong> <a href="/download_file?path=' + encodeURIComponent(data.metadata_path) + '">Download Metadata</a></p>' : '');
                    }} else {{
                        document.getElementById('status').textContent = 'Error: ' + data.error;
                        document.getElementById('result').innerHTML = '<p style="color: red;">Download failed: ' + data.error + '</p>';
                    }}
                    document.getElementById('progressBar').style.width = '100%';
                }})
                .catch(error => {{
                    document.getElementById('status').textContent = 'Error: ' + error.message;
                    document.getElementById('result').innerHTML = '<p style="color: red;">Download failed: ' + error.message + '</p>';
                }});
            }});
        </script>
    </body>
    </html>
    '''

@app.route('/download', methods=['POST'])
@require_local
@limiter.limit(RATE_LIMITS['DOWNLOAD'])
def download():
    """Enhanced download endpoint with security measures"""
    try:
        data = request.get_json()
        if not data:
            log_activity('INVALID_REQUEST', {'ip': request.remote_addr, 'error': 'Invalid JSON data'})
            return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400

        url = data.get('url')
        if not url or not validate_youtube_url(url):
            log_activity('INVALID_URL', {'ip': request.remote_addr, 'url': url})
            return jsonify({'success': False, 'error': 'Invalid YouTube URL'}), 400

        resolution = data.get('resolution', '1080p')
        if resolution not in ALLOWED_RESOLUTIONS:
            log_activity('INVALID_RESOLUTION', {'ip': request.remote_addr, 'resolution': resolution})
            return jsonify({'success': False, 'error': 'Invalid resolution'}), 400

        download_thumbnail = bool(data.get('thumbnail', True))
        save_metadata = bool(data.get('metadata', True))
        
        # Use temporary directory for web downloads
        temp_dir = tempfile.mkdtemp(prefix=TEMP_FILE_PREFIX)
        
        try:
            result = downloader_instance.download_video(
                url=url,
                save_path=temp_dir,
                target_resolution=resolution,
                download_thumbnail=download_thumbnail,
                save_metadata=save_metadata
            )
            
            if not result['success']:
                log_activity('DOWNLOAD_FAILED', {
                    'ip': request.remote_addr,
                    'url': url,
                    'error': result['error']
                })
                return jsonify(result), 400
                
            # Validate file paths and sizes
            for key in ['video_path', 'thumbnail_path', 'metadata_path']:
                if result.get(key):
                    file_path = os.path.abspath(result[key])
                    if not file_path.startswith(os.path.abspath(temp_dir)):
                        log_activity('PATH_TRAVERSAL_ATTEMPT', {
                            'ip': request.remote_addr,
                            'path': file_path
                        })
                        return jsonify({'success': False, 'error': 'Invalid file path'}), 400
                        
                    if os.path.getsize(file_path) > MAX_FILE_SIZE:
                        log_activity('FILE_SIZE_EXCEEDED', {
                            'ip': request.remote_addr,
                            'path': file_path,
                            'size': os.path.getsize(file_path)
                        })
                        return jsonify({'success': False, 'error': 'File too large'}), 400
                    
            log_activity('DOWNLOAD_SUCCESS', {
                'ip': request.remote_addr,
                'url': url,
                'title': result.get('title')
            })
            return jsonify(result)
            
        finally:
            # Clean up temporary directory after some time
            def cleanup():
                import time
                time.sleep(TEMP_FILE_LIFETIME)
                try:
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as e:
                    logger.error(f"Error cleaning up temp directory: {str(e)}")
            
            cleanup_thread = Thread(target=cleanup)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
    except Exception as e:
        logger.error(f"Download endpoint error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/download_file')
@require_local
@limiter.limit(RATE_LIMITS['FILE_RETRIEVAL'])
def download_file():
    """Enhanced file download endpoint with security measures"""
    try:
        file_path = request.args.get('path')
        if not file_path:
            log_activity('MISSING_FILE_PATH', {'ip': request.remote_addr})
            return "No file specified", 400
            
        # Validate file path
        abs_path = os.path.abspath(file_path)
        if not abs_path.startswith(tempfile.gettempdir()):
            log_activity('PATH_TRAVERSAL_ATTEMPT', {
                'ip': request.remote_addr,
                'path': file_path
            })
            return "Access denied", 403
            
        if not os.path.exists(abs_path):
            log_activity('FILE_NOT_FOUND', {
                'ip': request.remote_addr,
                'path': file_path
            })
            return "File not found", 404
            
        # Validate file size
        if os.path.getsize(abs_path) > MAX_FILE_SIZE:
            log_activity('FILE_SIZE_EXCEEDED', {
                'ip': request.remote_addr,
                'path': file_path,
                'size': os.path.getsize(abs_path)
            })
            return "File too large", 400
            
        # Validate file type
        if not validate_file_type(abs_path):
            log_activity('INVALID_FILE_TYPE', {
                'ip': request.remote_addr,
                'path': file_path
            })
            return "Invalid file type", 400
            
        log_activity('FILE_DOWNLOAD', {
            'ip': request.remote_addr,
            'path': file_path
        })
        return send_file(abs_path, as_attachment=True)
        
    except Exception as e:
        logger.error(f"File download error: {str(e)}")
        return str(e), 500

# Error handlers
@app.errorhandler(404)
def not_found(e):
    log_activity('NOT_FOUND', {'ip': request.remote_addr, 'path': request.path})
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    log_activity('SERVER_ERROR', {'ip': request.remote_addr, 'error': str(e)})
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    log_activity('RATE_LIMIT_EXCEEDED', {'ip': request.remote_addr, 'limit': str(e.description)})
    return jsonify({'error': f"Rate limit exceeded. {e.description}"}), 429

# Main execution
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "web":
        # Run Flask web interface
        print("Starting web interface on http://127.0.0.1:8080")
        app.run(debug=True, host='127.0.0.1', port=8080, threaded=True, use_reloader=False)
    elif len(sys.argv) > 1 and sys.argv[1] == "gui":
        # Run GUI
        gui = YouTubeDownloaderGUI()
        gui.run()
    else:
        # Command line usage
        print("YouTube Downloader Pro")
        print("Usage:")
        print("  python script.py gui    - Launch GUI interface")
        print("  python script.py web    - Launch web interface")
        print("  python script.py        - Show this help")
        
        # Example command line download
        url = input("Enter YouTube URL (or press Enter to see interfaces): ")
        if url.strip():
            downloader = YouTubeDownloader()
            result = downloader.download_video(url)
            if result['success']:
                print(f"Download completed: {result['title']}")
            else:
                print(f"Download failed: {result['error']}")
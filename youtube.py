import os
import json
import requests
from pytube import YouTube
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from threading import Thread
import subprocess
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile
from datetime import datetime
from flask_cors import CORS
import secrets

class YouTubeDownloader:
    def __init__(self):
        self.download_path = os.path.expanduser("~/Downloads/YouTube")
        self.ensure_directory_exists(self.download_path)
        self.progress_callback = None
        
    def ensure_directory_exists(self, path):
        """Create directory if it doesn't exist"""
        if not os.path.exists(path):
            os.makedirs(path)
    
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
        """Main download function with all features"""
        if not save_path:
            save_path = self.download_path
            
        self.ensure_directory_exists(save_path)
        
        try:
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
            
            # Convert to MP4 if needed (using ffmpeg)
            if video_path and not video_path.endswith('.mp4'):
                video_path = self.convert_to_mp4(video_path)
            
            return {
                'success': True,
                'video_path': video_path,
                'thumbnail_path': thumbnail_path,
                'metadata_path': metadata_path,
                'title': yt.title
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
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
CORS(app)  # Enable CORS for all routes
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Add a secret key
app.config['SESSION_COOKIE_SECURE'] = False  # Allow non-HTTPS cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True
downloader_instance = YouTubeDownloader()

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>YouTube Downloader Web</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { background: #f5f5f5; padding: 20px; border-radius: 10px; }
            input, select, button { padding: 10px; margin: 5px; border: 1px solid #ddd; border-radius: 5px; }
            input[type="text"] { width: 70%; }
            button { background: #007bff; color: white; cursor: pointer; }
            button:hover { background: #0056b3; }
            .progress { width: 100%; height: 20px; background: #ddd; border-radius: 10px; margin: 10px 0; }
            .progress-bar { height: 100%; background: #007bff; border-radius: 10px; width: 0%; }
            .status { margin: 10px 0; padding: 10px; background: #e7f3ff; border-radius: 5px; }
            .options { margin: 10px 0; }
            .checkbox { margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>YouTube Downloader Pro</h1>
            <form id="downloadForm">
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
            document.getElementById('downloadForm').addEventListener('submit', function(e) {
                e.preventDefault();
                
                const url = document.getElementById('url').value;
                const resolution = document.getElementById('resolution').value;
                const thumbnail = document.getElementById('thumbnail').checked;
                const metadata = document.getElementById('metadata').checked;
                
                if (!url) {
                    alert('Please enter a YouTube URL');
                    return;
                }
                
                // Show progress
                document.getElementById('progressContainer').style.display = 'block';
                document.getElementById('status').style.display = 'block';
                document.getElementById('status').textContent = 'Starting download...';
                
                // Send request
                fetch('/download', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        url: url,
                        resolution: resolution,
                        thumbnail: thumbnail,
                        metadata: metadata
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('status').textContent = 'Download completed: ' + data.title;
                        document.getElementById('result').innerHTML = 
                            '<h3>Download Successful!</h3>' +
                            '<p><strong>Title:</strong> ' + data.title + '</p>' +
                            '<p><strong>Video:</strong> <a href="/download_file?path=' + encodeURIComponent(data.video_path) + '">Download Video</a></p>' +
                            (data.thumbnail_path ? '<p><strong>Thumbnail:</strong> <a href="/download_file?path=' + encodeURIComponent(data.thumbnail_path) + '">Download Thumbnail</a></p>' : '') +
                            (data.metadata_path ? '<p><strong>Metadata:</strong> <a href="/download_file?path=' + encodeURIComponent(data.metadata_path) + '">Download Metadata</a></p>' : '');
                    } else {
                        document.getElementById('status').textContent = 'Error: ' + data.error;
                        document.getElementById('result').innerHTML = '<p style="color: red;">Download failed: ' + data.error + '</p>';
                    }
                    document.getElementById('progressBar').style.width = '100%';
                })
                .catch(error => {
                    document.getElementById('status').textContent = 'Error: ' + error.message;
                    document.getElementById('result').innerHTML = '<p style="color: red;">Download failed: ' + error.message + '</p>';
                });
            });
        </script>
    </body>
    </html>
    '''

@app.route('/download', methods=['POST'])
def download():
    data = request.json
    url = data.get('url')
    resolution = data.get('resolution', '1080p')
    download_thumbnail = data.get('thumbnail', True)
    save_metadata = data.get('metadata', True)
    
    if not url:
        return jsonify({'success': False, 'error': 'No URL provided'})
    
    # Use temporary directory for web downloads
    temp_dir = tempfile.mkdtemp()
    
    result = downloader_instance.download_video(
        url=url,
        save_path=temp_dir,
        target_resolution=resolution,
        download_thumbnail=download_thumbnail,
        save_metadata=save_metadata
    )
    
    return jsonify(result)

@app.route('/download_file')
def download_file():
    file_path = request.args.get('path')
    if file_path and os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File not found", 404

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
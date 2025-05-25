# YouTube Downloader Pro

A Python-based YouTube video downloader with both GUI and web interfaces.

## ⚠️ Important Security Note
This application is designed for personal use on your local machine only. The web interface uses a development server that is NOT suitable for production deployment.

### Security Features
- Local-only access (127.0.0.1)
- Rate limiting to prevent abuse
- Input validation for YouTube URLs
- Secure file handling with temporary directories
- Automatic cleanup of temporary files
- Request size limiting
- Security headers (XSS protection, CSP, etc.)
- CORS protection
- Session security
- Path traversal protection
- CSRF protection
- File type validation
- File hash verification
- Comprehensive logging
- Sanitized inputs
- Temporary file cleanup
- Maximum file size limits
- Secure cookie configuration
- HTTP security headers
- Content Security Policy (CSP)
- MIME type validation

## Features
- Download YouTube videos in various resolutions
- Download video thumbnails
- Save video metadata
- GUI interface
- Web interface (local only)
- Resume interrupted downloads
- Automatic format conversion to MP4

## Requirements
- Python 3.x
- ffmpeg
- libmagic

## Installation

1. Clone the repository:
```bash
git clone [your-repo-url]
cd ytd
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install pytube requests flask werkzeug flask-cors flask-limiter python-magic bleach
```

4. Install system dependencies:
- macOS:
  ```bash
  brew install ffmpeg libmagic
  ```
- Windows:
  - Download ffmpeg from https://ffmpeg.org/
  - Install libmagic via conda or binary distribution
- Linux:
  ```bash
  sudo apt-get install ffmpeg libmagic1
  ```

5. (Optional) Set environment variables:
```bash
export FLASK_SECRET_KEY="your-secret-key-here"  # Optional: Will generate random key if not set
```

## Usage

### Web Interface (Recommended)
```bash
python3 youtube.py web
```
Then open http://127.0.0.1:8080 in your browser

### GUI Interface
```bash
python3 youtube.py gui
```

### Security Considerations
- This application is for personal use only
- The web interface should only be accessed locally (127.0.0.1)
- Never expose the web interface to the internet
- Keep your dependencies updated
- Don't share downloaded content without permission
- Rate limits: 
  - 200 requests per day
  - 50 requests per hour
  - 10 downloads per minute
  - 30 file retrievals per minute
- Maximum request size: 1MB
- Maximum download file size: 1GB
- Temporary files are automatically cleaned up after 5 minutes
- All downloads are logged and monitored
- File types are strictly validated
- CSRF tokens protect against cross-site request forgery
- Input sanitization prevents XSS attacks
- Path traversal protection is enforced
- File hashes are verified for integrity

### Security Best Practices
1. Always run in a virtual environment
2. Keep the application and its dependencies updated
3. Don't disable any security features
4. Don't modify the rate limits unless you have a good reason
5. Don't share your FLASK_SECRET_KEY
6. Regularly check the logs for suspicious activity
7. Keep the security_config.py file secure
8. Don't commit sensitive files (follow .gitignore)
9. Use HTTPS if deploying (not recommended)
10. Monitor system resources and disk usage
11. Regularly clean up old log files
12. Keep the host system updated and secure

### Security Configuration
The application uses a `security_config.py` file that contains all security-related settings. This file should be:
- Never committed to version control with production values
- Kept with restricted permissions
- Regularly audited for appropriate values
- Modified only by authorized users
- Backed up securely

### Logging and Monitoring
The application maintains detailed logs of:
- All download attempts
- File operations
- Security violations
- Rate limit breaches
- System errors
- User activity

Logs are automatically rotated to prevent disk space issues.

## License
MIT License

Copyright (c) 2025 Dominic Smith

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Disclaimer
This tool is for personal use only. Users are responsible for complying with YouTube's terms of service and applicable copyright laws.

## Security Reporting
If you discover any security issues, please do not create a public GitHub issue. Instead, please report them to domsmith343@gmail.com.

## Security Updates
Security updates will be released as soon as vulnerabilities are discovered. Users should:
1. Watch the repository for updates
2. Regularly check for new releases
3. Apply security patches promptly
4. Monitor security advisories 

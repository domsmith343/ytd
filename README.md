# YouTube Downloader Pro

A Python-based YouTube video downloader with both GUI and web interfaces.

## ⚠️ Important Security Note
This application is designed for personal use on your local machine only. The web interface uses a development server that is NOT suitable for production deployment.

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
pip install pytube requests flask werkzeug flask-cors
```

4. Install ffmpeg:
- macOS: `brew install ffmpeg`
- Windows: Download from https://ffmpeg.org/
- Linux: `sudo apt-get install ffmpeg`

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

## License
[Your chosen license]

## Disclaimer
This tool is for personal use only. Users are responsible for complying with YouTube's terms of service and applicable copyright laws. 
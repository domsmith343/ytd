from pytube import YouTube
import tkinter as tk
from tkinter import filedialog

def download_video(url, save_path):
    try:
        yt = YouTube(url)
        streams = yt.streams.filter(progressive=True, file_extension='mp4')
        highest_res = streams.get_highest_resolution()
        highest_res.download(output_path=save_path)  # Fix: Use highest_res instead of highest_res_stream
        print("Download completed!")
        
    except Exception as e:
        print(e)
        
url = "https://youtu.be/1xCkl9ZcQp4?si=Uztp_t6PszYXS3Ly"
save_path = "users/user/downloads" #add path

download_video(url, save_path)

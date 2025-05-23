import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Change this for security
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root@127.0.0.1:3307/python'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    #########
    UPLOAD_FOLDER = 'static/uploads' # For user profile pictures
    CHAT_UPLOAD_FOLDER = 'static/chat_uploads' # For chat uploaded images
    STICKER_FOLDER = 'static/stickers' # For pre-defined stickers
    
    # Max content length for file uploads (e.g., 16 MB)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # Allowed extensions for uploaded image files
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

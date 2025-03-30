import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Change this for security
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root@127.0.0.1:3307/python'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

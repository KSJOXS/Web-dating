from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import Enum as SQLAlchemyEnum 

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)  # Primary key is 'user_id'
    username = db.Column(db.String(80), unique=True, nullable=False)
    last_name = db.Column(db.String(50)) 
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50))
    gender = db.Column(db.Enum('Male', 'Female', 'Other'), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(255), default="default_profile.png")
    location = db.Column(db.String(100))
    interests = db.Column(db.Text)

    likes_sent = db.relationship('Like', foreign_keys='Like.sender_id', back_populates='user_who_sent_like', lazy=True)
    likes_received = db.relationship('Like', foreign_keys='Like.receiver_id', back_populates='user_who_received_like', lazy=True)
    matches1 = db.relationship('Match', foreign_keys='Match.user1_id', backref='user1', lazy=True)
    matches2 = db.relationship('Match', foreign_keys='Match.user2_id', backref='user2', lazy=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # One-to-one relationship to Profile
    profile = db.relationship('Profile', backref='user', uselist=False)

    def get_id(self):
        return str(self.user_id)  # Use 'user_id' here, not 'id'
    



class Profile(db.Model):
    __tablename__ = 'profiles'

    profile_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), unique=True, nullable=False)  # Corrected ForeignKey reference to 'user_id'
    name = db.Column(db.String(150))
    age = db.Column(db.Integer)
    date_of_birth = db.Column(db.Date, nullable=True)

    
    interests = db.Column(db.Text)
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(255), nullable=True)
    location = db.Column(db.String(255), nullable=True)
    

class Like(db.Model):
    __tablename__ = 'likes'
    like_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    status = db.Column(SQLAlchemyEnum('Liked', 'Disliked', name='like_status_enum_final'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_who_sent_like = db.relationship('User', foreign_keys=[sender_id], back_populates='likes_sent')
    user_who_received_like = db.relationship('User', foreign_keys=[receiver_id], back_populates='likes_received')



class Match(db.Model):
    __tablename__ = 'matches'
    match_id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    match_status = db.Column(db.Enum('Matched', 'Unmatched'), nullable=False, default='Unmatched')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lower_user_id = db.Column(db.Integer, nullable=False)
    higher_user_id = db.Column(db.Integer, nullable=False)

class Message(db.Model):
    __tablename__ = 'messages'

    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    message_text = db.Column(db.Text, nullable=False) # ### แก้ไข: ต้องเป็น 'message_text'
    sent_at = db.Column(db.DateTime, default=db.func.current_timestamp()) # ### แก้ไข: ต้องเป็น 'sent_at'
    read_status = db.Column(db.Boolean, default=False) # ถ้ามีคอลัมน์นี้ใน DB ของคุณ (จาก Diagram คือ tinyint(1))
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='messages_sent')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='messages_received')

    def __repr__(self):
        return f"<Message from {self.sender_id} to {self.receiver_id} at {self.timestamp}>"
    
    
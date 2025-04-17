from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

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
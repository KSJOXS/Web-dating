from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    gender = db.Column(db.Enum('Male', 'Female', 'Other'), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(255), default="default_profile.png")
    location = db.Column(db.String(100))
    interests = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    

    def get_id(self):
        return str(self.user_id)


class Profile(db.Model):
    __tablename__ = 'profiles'

    profile_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), unique=True, nullable=False)  # Foreign key to users
    name = db.Column(db.String(150))
    age = db.Column(db.Integer)
    gender = db.Column(db.Enum('MALE', 'FEMALE', 'OTHER'))
    interests = db.Column(db.Text)
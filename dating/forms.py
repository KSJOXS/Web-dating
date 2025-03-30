from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, FileField, ValidationError, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 
class RegisterForm(FlaskForm):
    username = StringField(
        'Username', 
        validators=[
            DataRequired(message="Username is required."), 
            Length(min=3, max=50, message="Username must be between 3 and 50 characters.")
        ]
    )
    email = StringField(
        'Email Address', 
        validators=[
            DataRequired(message="Email is required."), 
            Email(message="Enter a valid email address."), 
            Length(max=150, message="Email must be under 150 characters.")
        ]
    )
    password = PasswordField(
        'Password', 
        validators=[
            DataRequired(message="Password is required."), 
            Length(min=6, max=255, message="Password must be at least 6 characters.")
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password', 
        validators=[
            DataRequired(message="Please confirm your password."), 
            EqualTo('password', message="Passwords must match.")
        ]
    )
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField(
        "Email Address", 
        validators=[
            DataRequired(message="Email is required."), 
            Email(message="Enter a valid email address.")
        ]
    )
    password = PasswordField(
        "Password", 
        validators=[
            DataRequired(message="Password is required.")
        ]
    )
    submit = SubmitField("Login")



class ProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    date_of_birth = DateField('Date of Birth', validators=[DataRequired()])  # Add date_of_birth field
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    profile_picture = FileField('Profile Picture')
    location = StringField('Location', validators=[Length(max=100)])
    interests = TextAreaField('Interests', validators=[Length(max=500)])
    submit = SubmitField('Save Profile')
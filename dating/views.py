from flask import render_template, redirect, url_for, flash
import os
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import app, db, login_manager
from werkzeug.security import check_password_hash
from models import User, Profile
from forms import LoginForm, RegisterForm, ProfileForm # Import ProfileForm from the correct module

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/explore')
def explore():
    return render_template('explore.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data, password=form.password.data)  
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
# Define the upload folder path
UPLOAD_FOLDER = os.path.join(app.root_path, 'static/uploads')

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/create_profile', methods=['GET', 'POST'])
@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    form = ProfileForm()

    if form.validate_on_submit():
        # Process profile picture upload
        profile_picture_filename = None
        if form.profile_picture.data:
            file = form.profile_picture.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                profile_picture_filename = os.path.join(UPLOAD_FOLDER, filename)

        # Update or create the profile
        if current_user.profile:
            # Update existing profile
            current_user.profile.first_name = form.first_name.data
            current_user.profile.last_name = form.last_name.data
            current_user.profile.gender = form.gender.data
            current_user.profile.date_of_birth = form.date_of_birth.data
            current_user.profile.bio = form.bio.data
            current_user.profile.profile_picture = profile_picture_filename
            current_user.profile.location = form.location.data
            current_user.profile.interests = form.interests.data
        else:
            # Create a new profile
            profile = Profile(
                user_id=current_user.user_id,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                gender=form.gender.data,
                date_of_birth=form.date_of_birth.data,
                bio=form.bio.data,
                profile_picture=profile_picture_filename,
                location=form.location.data,
                interests=form.interests.data
            )
            db.session.add(profile)

        db.session.commit()
        flash('Profile saved successfully!', 'success')
        return redirect(url_for('profile'))  # Redirect to the profile view

    return render_template('create_profile.html', form=form)
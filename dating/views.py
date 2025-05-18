from flask import render_template, redirect, url_for, flash, session, request, jsonify
import logging  # Import the logging module
import os
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import app, db, login_manager
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, Like, Message, Match
from forms import LoginForm, RegisterForm, ProfileForm # Import ProfileForm from the correct module
from sqlalchemy import and_, or_  # Import and_ and or_ from sqlalchemy
from sqlalchemy.exc import SQLAlchemyError  # Import SQLAlchemyError

from flask_socketio import SocketIO, emit, join_room
from datetime import datetime
# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Dictionary to keep track of users in chat rooms
users_in_chat = {}
users_in_chat = {}

# Define the save_message function to store messages
def save_message(sender_id, recipient_id, message):
    # Example: Save the message to the database
    # Replace this with your actual database logic
    print(f"Saving message from {sender_id} to {recipient_id}: {message}")

socketio = SocketIO(app, cors_allowed_origins="*") 
#socketio = SocketIO(app)

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data['sender_id']
    recipient_id = data['recipient_id']
    message = data['message']

    # บันทึกข้อความลงในฐานข้อมูล (ตามที่คุณทำอยู่แล้ว)
    save_message(sender_id, recipient_id, message)

    # สร้างชื่อ Room (เรียง ID ผู้ใช้แล้วเชื่อมด้วย '-')
    room = '-'.join(sorted([str(sender_id), str(recipient_id)]))

    # ส่งข้อความไปยัง Room ที่เกี่ยวข้อง (รวมทั้งผู้ส่ง)
    emit('receive_message', {'sender_id': sender_id, 'message': message}, room=room)

@socketio.on('join_chat')
def on_join(data):
    user_id = data.get('user_id') # ### แก้ไข: ใช้ .get() เพื่อป้องกัน KeyError ถ้าไม่มี user_id
    room_name = data.get('room') # 'room' is the sorted ID string from client

    if user_id and room_name:
        join_room(room_name)
        print(f"User {user_id} (SID: {request.sid}) joined room: {room_name}")
    else:
        logger.error(f"Invalid join_chat data: {data}") # ### เพิ่ม: logging เพื่อ debug ข้อมูลที่ไม่ถูกต้อง
from flask_socketio import leave_room, rooms  # <-- Add leave_room import at the top of this block

@socketio.on('leave_chat') # ### เพิ่ม: leave_chat handler
def on_leave(data):
    user_id = data.get('user_id')
    room_name = data.get('room')
    if user_id and room_name:
        # ตรวจสอบว่า request.sid ยังอยู่ใน room นี้หรือไม่ ก่อนจะ leave
        if request.sid in rooms(sid=request.sid, namespace='/') and room_name in rooms(sid=request.sid, namespace='/'):
             leave_room(room_name)
             print(f"User {user_id} (SID: {request.sid}) left room: {room_name}")
        else:
            print(f"User {user_id} (SID: {request.sid}) was not in room {room_name} to leave.")

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('send_message')
def handle_send_message(data):
    try:
        sender_id = data.get('sender_id')
        recipient_id = data.get('recipient_id')
        message_text = data.get('message') # ชื่อตัวแปรดีแล้ว ตรงกับ DB

        if sender_id is None or recipient_id is None or message_text is None:
            logger.error(f"Missing data for send_message: sender_id={sender_id}, recipient_id={recipient_id}, message={message_text}")
            emit('error', {'message': 'Missing message data.'})
            return

        # --- เริ่มต้น logic การบันทึกข้อความลง DB ---
        new_message = Message(
            sender_id=sender_id,
            receiver_id=recipient_id, # CORRECT: ใช้ receiver_id ตาม DB Schema
            message_text=message_text, # CORRECT: ใช้ message_text ตาม DB Schema
            sent_at=datetime.utcnow() # เพิ่ม sent_at เพื่อบันทึกเวลา
        )
        db.session.add(new_message)
        db.session.commit()
        # --- สิ้นสุด logic การบันทึกข้อความลง DB ---

        room = '-'.join(sorted([str(sender_id), str(recipient_id)]))

        emit('receive_message', {
            'sender_id': sender_id,
            'recipient_id': recipient_id, # เก็บไว้ให้ JS client
            'message': message_text,
            'timestamp': datetime.utcnow().isoformat() # ส่ง timestamp กลับไปให้ client ด้วย
        }, room=room)
        print(f"Message from {sender_id} to {recipient_id} sent to room {room}: {message_text}")

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"SQLAlchemy Error saving message: {str(e)}")
        emit('error', {'message': 'Failed to send message due to database error.'})
    except Exception as e:
        logger.error(f"Unexpected error in handle_send_message: {str(e)}")
        emit('error', {'message': 'An unexpected error occurred.'})




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
        email = form.email.data
        password = form.password.data
        print(f"Attempting login with email: '{email}' and password: '{password}'")
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"User found with email: '{user.email}'")
            if check_password_hash(user.password_hash, password):
                print("Password matches!")
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for('profile'))
            else:
                print("Password does NOT match!")
                flash("Invalid email or password", "danger")
        else:
            print("No user found with that email!")
            flash("Invalid email or password", "danger")
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)  # <--- THIS IS THE MISSING LINE!
        flash("Registration successful and you are now logged in!", "success")
        return redirect(url_for('profile'))  # Redirect to the user's profile page (or another appropriate page)

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

"""
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
                name=form.first_name.data,              
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
"""

@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    form = ProfileForm()

    if request.method == 'GET':
        # Populate form fields with existing user data
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name  # if last_name is added
        form.gender.data = current_user.gender
        form.date_of_birth.data = current_user.date_of_birth
        form.bio.data = current_user.bio
        form.location.data = current_user.location
        form.interests.data = current_user.interests

    if form.validate_on_submit():
        # Handle profile picture upload
        profile_picture_filename = current_user.profile_picture
        if form.profile_picture.data:
            file = form.profile_picture.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                profile_picture_filename = filename  # save filename only

        # Update current user info
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data  # if using
        current_user.gender = form.gender.data
        current_user.date_of_birth = form.date_of_birth.data
        current_user.bio = form.bio.data
        current_user.profile_picture = profile_picture_filename
        current_user.location = form.location.data
        current_user.interests = form.interests.data

        db.session.commit()
        flash('Profile saved successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('create_profile.html', form=form)


@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/learn')
def learn():
    return render_template('learn.html')

@app.route('/chat')
@login_required
def chat():
    matches = Match.query.filter(
        ((Match.user1_id == current_user.user_id) | (Match.user2_id == current_user.user_id)),
        Match.match_status == 'Matched'
    ).all()

    matched_data = []
    for match in matches:
        other_user_id = None
        if match.user1_id == current_user.user_id:
            other_user_id = match.user2_id
        else:
            other_user_id = match.user1_id

        if other_user_id:
            other_user = User.query.get(other_user_id)
            if other_user:
                matched_data.append({'match': match, 'user': other_user})

    return render_template('chat.html', matches=matched_data)

@app.route('/matches')
@login_required
def matches():
    liked_ids = [like.receiver_id for like in Like.query.filter(
        Like.sender_id == current_user.user_id,
        Like.status == 'Liked'
    ).all()]
    users = User.query.filter(User.user_id != current_user.user_id).all()
    matches_data = [
        {
            'id': user.user_id,
            'name': user.first_name or user.username,
            'gender': user.gender,
            'interests': user.interests,
            'profile_picture': user.profile_picture,
            'is_liked': user.user_id in liked_ids
        }
        for user in users
    ]
    return render_template('matches.html', matches=matches_data, profile=current_user)
    
@app.route('/safety')
def safety():
    return render_template('safety.html')

@app.route('/submit_report', methods=['POST'])
def submit_report():
    if request.method == 'POST':
        reporter_email = request.form['reporter_email']
        reported_user = request.form['reported_user']
        category = request.form['category']
        description = request.form['description']

        # Process the report data - e.g., save to a database, send an email to admins
        print(f"Safety Report Received:")
        print(f"Reporter Email: {reporter_email}")
        print(f"Reported User: {reported_user}")
        print(f"Category: {category}")
        print(f"Description: {description}")

        # Optionally, provide a feedback message to the user
        return render_template('report_submitted.html') # You'll need to create this template
    else:
        return redirect(url_for('safety')) # Redirect if accessed with GET

   

# ใน app.py
@app.route('/get_messages/<int:other_user_id>', methods=['GET'])
@login_required
def get_messages(other_user_id):
    try:
        messages = Message.query.filter(
            ((Message.sender_id == current_user.user_id) & (Message.receiver_id == other_user_id)) | # ### แก้ไข: ใช้ Message.receiver_id
            ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.user_id))  # ### แก้ไข: ใช้ Message.receiver_id
        ).order_by(Message.sent_at.asc()).all() # ### แก้ไข: ใช้ Message.sent_at (เพื่อเรียงลำดับ)

        messages_data = [
            {
                'message': msg.message_text, # ### แก้ไข: ใช้ msg.message_text
                'sender_id': msg.sender_id,
                'timestamp': msg.sent_at.isoformat() # ### แก้ไข: ใช้ msg.sent_at (สำหรับ timestamp)
            }
            for msg in messages
        ]
        return jsonify(messages_data)
    except SQLAlchemyError as e:
        logger.error(f"SQLAlchemy Error fetching messages: {str(e)}")
        return jsonify({"error": "Failed to fetch messages."}), 500
    except Exception as e:
        logger.error(f"Unexpected error fetching messages: {str(e)}")
        return jsonify({"error": "An unexpected error occurred."}), 500

@app.route('/like_user', methods=['POST'])
@login_required
def like_user():
    data = request.get_json()
    liked_user_id = data.get('match_id')  # เปลี่ยนชื่อตัวแปรให้สื่อความหมาย

    if not liked_user_id:
        return jsonify({'success': False, 'message': 'Missing user ID to like.'}), 400

    try:
        liked_user = User.query.get(liked_user_id)
        if not liked_user:
            return jsonify({'success': False, 'message': 'Invalid user to like.'}), 400

        # ตรวจสอบว่าผู้ใช้ปัจจุบันยังไม่ได้กดไลค์ผู้ใช้คนนี้
        existing_like = Like.query.filter_by(
            sender_id=current_user.user_id,
            receiver_id=liked_user.user_id
        ).first()

        if not existing_like:
            new_like = Like(sender_id=current_user.user_id, receiver_id=liked_user.user_id, status='Liked')
            db.session.add(new_like)
            db.session.commit()

            # ตรวจสอบว่าผู้ใช้ที่ถูกไลค์ ได้ไลค์กลับมาหรือไม่
            reverse_like = Like.query.filter_by(
                sender_id=liked_user.user_id,
                receiver_id=current_user.user_id
            ).first()

            if reverse_like and reverse_like.status == 'Liked':
                # สร้าง Match record ถ้ามีการไลค์สวนกลับ
                existing_match = Match.query.filter(
                    ((Match.user1_id == current_user.user_id) & (Match.user2_id == liked_user.user_id)) |
                    ((Match.user1_id == liked_user.user_id) & (Match.user2_id == current_user.user_id))
                ).first()
                if not existing_match:
                    new_match = Match(
                        user1_id=min(current_user.user_id, liked_user.user_id),
                        user2_id=max(current_user.user_id, liked_user.user_id),
                        match_status='Matched',
                        created_at=datetime.utcnow()
                    )
                    db.session.add(new_match)
                    db.session.commit()
                    return jsonify({'success': True, 'message': f'You matched with {liked_user.first_name}!'})
                else:
                    return jsonify({'success': True, 'message': f'You liked {liked_user.first_name}!'})
            else:
                return jsonify({'success': True, 'message': f'You liked {liked_user.first_name}!'})
        else:
            return jsonify({'success': False, 'message': 'You have already liked this user.'})

    except Exception as e:
        db.session.rollback()
        print(f"Error liking user: {e}")
        return jsonify({'success': False, 'message': 'Something went wrong while liking this user.'}), 500

@app.route('/unlike_user', methods=['POST'])
@login_required
def unlike_user():
    data = request.get_json()
    user_to_unlike_id = data.get('user_id')
    if user_to_unlike_id:
        like = Like.query.filter_by(liker_id=current_user.user_id, liked_id=user_to_unlike_id).first()
        if like:
            like.status = 'Disliked'  # Or db.session.delete(like)
            db.session.commit()
            return jsonify({'success': True, 'message': f'You unliked user with ID {user_to_unlike_id}.'})
        else:
            return jsonify({'success': False, 'message': 'Like record not found.'})
    return jsonify({'success': False, 'message': 'Invalid request.'})

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
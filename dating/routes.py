from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,login_user,login_required,logout_user
from models import db,User
from forms import RegistrationForm,LoginForm
from config import Config
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)


db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully!", "success")
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Login failed. Check email and password.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))



@app.route('/explore')  # ✅ Make sure this route exists
def explore():
    return render_template('explore.html')

with app.app_context():
    db.create_all()

    if not User.query.first():  # Only add fake users if the database is empty
        fake_users = [
            User(username="Alice", email="alice@example.com", password=bcrypt.generate_password_hash("test123").decode("utf-8")),
            User(username="Bob", email="bob@example.com", password=bcrypt.generate_password_hash("test123").decode("utf-8")),
            User(username="Charlie", email="charlie@example.com", password=bcrypt.generate_password_hash("test123").decode("utf-8")),
        ]
        db.session.add_all(fake_users)
        db.session.commit()
        print("✅ Fake users added for testing!")

        
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # สร้างฐานข้อมูลอัตโนมัติ
    app.run(debug=True)
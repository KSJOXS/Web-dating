from flask import render_template, redirect, url_for, flash
from flask.views import MethodView
from flask_login import login_required, login_user, logout_user, current_user
from models import User, db
from forms import RegistrationForm, LoginForm
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

# Home Page
class HomeView(MethodView):
    def get(self):
        return render_template("home.html")

# Explore Matches Page
class ExploreView(MethodView):
    def get(self):
        return render_template('explore.html')

# User Profile Page
class ProfileView(MethodView):
    @login_required
    def get(self):
        return render_template("profile.html", user=current_user)

# Registration Page
class RegisterView(MethodView):
    def get(self):
        form = RegistrationForm()
        return render_template("register.html", form=form)

    def post(self):
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for('login'))
        return render_template("register.html", form=form)

# Login Page
class LoginView(MethodView):
    def get(self):
        form = LoginForm()
        return render_template("login.html", form=form)

    def post(self):
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for('profile'))
            else:
                flash("Login failed. Check email and password.", "danger")
        return render_template("login.html", form=form)

# Logout Route
class LogoutView(MethodView):
    @login_required
    def get(self):
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for('home'))

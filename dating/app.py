from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config
from models import db
from views import HomeView, ExploreView, ProfileView, RegisterView, LoginView, LogoutView

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database and login manager
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Add URL rules for class-based views
app.add_url_rule('/', view_func=HomeView.as_view('home'))
app.add_url_rule('/explore', view_func=ExploreView.as_view('explore'))
app.add_url_rule('/profile', view_func=ProfileView.as_view('profile'))
app.add_url_rule('/register', view_func=RegisterView.as_view('register'), methods=['GET', 'POST'])
app.add_url_rule('/login', view_func=LoginView.as_view('login'), methods=['GET', 'POST'])
app.add_url_rule('/logout', view_func=LogoutView.as_view('logout'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database if it doesn't exist
    app.run(debug=True)

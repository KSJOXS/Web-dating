from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config
from models import db, User



app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)


# 🔹 Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
 # Redirect users to login page if not authenticated
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


from views import *

if __name__ == '__main__':
    app.run(debug=True)                   
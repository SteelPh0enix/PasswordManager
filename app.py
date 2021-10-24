from flask import Flask
from database import db, User
from flask_login import LoginManager

app = Flask(__name__,
            static_url_path='',
            static_folder='static',
            template_folder='templates')
app.config.from_pyfile('.env')
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

import routes
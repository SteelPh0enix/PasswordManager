from flask import Flask
from database import db

app = Flask(__name__,
            static_url_path='',
            static_folder='static',
            template_folder='templates')
app.config.from_pyfile('.env')
db.init_app(app)

with app.app_context():
    db.create_all()

import routes
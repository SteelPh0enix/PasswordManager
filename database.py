from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()
class User(db.Model, UserMixin):
    __tablename__ = 'Users'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    login = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    password_salt = db.Column(db.String, nullable=True)
    password_security_method = db.Column(db.Integer, nullable=False)

    def __repr__(self) -> str:
        return '<User(id="{0}", login="{1}")>'.format(self.id, self.login)


class PasswordEntry(db.Model):
    __tablename__ = 'PasswordEntries'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    title = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    login = db.Column(db.String)
    web_address = db.Column(db.String)
    description = db.Column(db.String)

    def __repr__(self) -> str:
        return '<PasswordEntry(id="{0}", user_id="{1}", login="{2}", web_address="{3}", description="{4}")>'.format(
            self.id, self.user_id, self.login, self.web_address, self.description)

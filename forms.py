from wtforms import Form, StringField, PasswordField, RadioField, validators
from wtforms.csrf.session import SessionCSRF
from app_types import MasterPasswordStorageMethod
from flask import session
from app import app


class BaseForm(Form):
    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = app.config['CSRF_SECRET_KEY']

        @property
        def csrf_context(self):
            return session


class RegistrationForm(BaseForm):
    username = StringField(
        'Username', [validators.DataRequired(), validators.Length(min=3, max=64)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=6),
        validators.EqualTo('confirm_password', message='Passwords must match!')
    ])
    confirm_password = PasswordField(
        'Repeat password', [validators.DataRequired()])
    password_storage_method = RadioField('Password storage method', [validators.DataRequired()], choices=[(
        MasterPasswordStorageMethod.HASH, 'Salted hash'),
        (MasterPasswordStorageMethod.HMAC, 'HMAC')
    ])


class LoginForm(BaseForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

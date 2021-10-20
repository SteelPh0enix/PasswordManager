from wtforms import Form, StringField, PasswordField, RadioField, validators
from app_types import MasterPasswordStorageMethod


class RegistrationForm(Form):
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


class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

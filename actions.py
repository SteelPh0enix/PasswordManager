from typing import Hashable, Tuple
from database import PasswordEntry, User, db
from app_types import MasterPasswordStorageMethod
from enum import Enum
import data_security as sec
from app import app
from hashlib import md5


class RegisterError(Enum):
    OK = 0,
    USER_ALREADY_EXISTS = 1,
    INVALID_SECURITY_METHOD = 2

    def __str__(self):
        if self == RegisterError.OK:
            return 'No error'
        elif self == RegisterError.USER_ALREADY_EXISTS:
            return 'User with the same username already exists'
        elif self == RegisterError.INVALID_SECURITY_METHOD:
            return 'Invalid security method'


class UserCredentialsError(Enum):
    OK = 0,
    INVALID_USERNAME = 1,
    INVAID_PASSWORD = 2,
    INVALID_SECURITY_METHOD = 3

    def __str__(self):
        if self == UserCredentialsError.OK:
            return 'No error'
        elif self == UserCredentialsError.INVALID_USERNAME:
            return 'Invalid username'
        elif self == UserCredentialsError.INVAID_PASSWORD:
            return 'Invalid password'
        elif self == UserCredentialsError.INVALID_SECURITY_METHOD:
            return 'Invalid security method'


def register_user(username: str, password: str, security_type_value: int) -> RegisterError:
    security_type = MasterPasswordStorageMethod(security_type_value)
    print('Registering user {0} with security type {1}'.format(
        username, security_type))
    existing_user = User.query.filter_by(login=username).first()
    if existing_user is not None:
        return RegisterError.USER_ALREADY_EXISTS

    encoded_password = password.encode('UTF-8')
    security_key = app.config['SECRET_KEY']
    user = None

    if security_type == MasterPasswordStorageMethod.HMAC:
        secured_password = sec.secure_data_hmac(encoded_password, security_key)
        user = User(login=username, password_hash=secured_password,
                    password_security_method=int(security_type))
    elif security_type == MasterPasswordStorageMethod.HASH:
        secured_password, password_salt = sec.secure_data_encrypted_hash(
            encoded_password, security_key)
        user = User(login=username, password_hash=secured_password,
                    password_salt=password_salt, password_security_method=int(security_type))
    else:
        return RegisterError.INVALID_SECURITY_METHOD

    db.session.add(user)
    db.session.commit()

    return RegisterError.OK


def check_user_credentials(username: str, password: str) -> Tuple[UserCredentialsError, User]:
    user = User.query.filter_by(login=username).first()
    if user is None:
        return UserCredentialsError.INVALID_USERNAME, None

    encoded_password = password.encode('UTF-8')
    security_key = app.config['SECRET_KEY']
    if user.password_security_method == int(MasterPasswordStorageMethod.HMAC):
        encrypted_password = sec.secure_data_hmac(
            encoded_password, security_key)
        if user.password_hash != encrypted_password:
            return UserCredentialsError.INVAID_PASSWORD, None
    elif user.password_security_method == int(MasterPasswordStorageMethod.HASH):
        if not sec.compare_data_encrypted_hash(encoded_password, user.password_hash, user.password_salt, security_key):
            return UserCredentialsError.INVAID_PASSWORD, None
    else:
        return UserCredentialsError.INVALID_SECURITY_METHOD, None

    return UserCredentialsError.OK, user


def add_password_entry(user: User, title: str, password: str, login: str, web_address: str, description: str):
    encoded_user_password = user.password_hash
    encoded_password = password.encode('UTF-8')
    security_key = app.config['SECRET_KEY']

    hasher = md5()
    hasher.update(encoded_user_password)
    hasher.update(security_key)
    password_key = hasher.digest()

    encrypted_password = sec.encrypt_data_aes(encoded_password, password_key)

    entry = PasswordEntry(
        title=title,
        password=encrypted_password,
        user_id=user.id,
        login=login,
        web_address=web_address,
        description=description
    )

    db.session.add(entry)
    db.session.commit()


def get_password_entry(user: User, password_id: str) -> str:
    password = PasswordEntry.query.filter_by(
        id=password_id, user_id=user.id).first()
    if password is None:
        return ''

    encoded_user_password = user.password_hash
    security_key = app.config['SECRET_KEY']

    hasher = md5()
    hasher.update(encoded_user_password)
    hasher.update(security_key)
    password_key = hasher.digest()

    return sec.decrypt_data_aes(password.password, password_key)

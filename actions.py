from database import PasswordEntry, User, db
from app_types import MasterPasswordStorageMethod
from enum import Enum
import data_security as sec
from app import app


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
        print('sec type: hmac')
        secured_password = sec.secure_data_hmac(encoded_password, security_key)
        user = User(login=username, password_hash=secured_password,
                    password_security_method=int(security_type))
    elif security_type == MasterPasswordStorageMethod.HASH:
        print('sec type: hash')
        secured_password, password_salt = sec.secure_data_encrypted_hash(
            encoded_password, security_key)
        user = User(login=username, password_hash=secured_password,
                    password_salt=password_salt, password_security_method=int(security_type))
    else:
        print('invalid sec type')
        return RegisterError.INVALID_SECURITY_METHOD

    db.session.add(user)
    db.session.commit()

    return RegisterError.OK


def check_user_credentials(username: str, password: str) -> UserCredentialsError:
    user = User.query.filter_by(login=username).first()
    if user is None:
        return UserCredentialsError.INVALID_USERNAME

    encoded_password = password.encode('UTF-8')
    security_key = app.config['SECRET_KEY']
    if user.password_security_method == int(MasterPasswordStorageMethod.HMAC):
        encrypted_password = sec.secure_data_hmac(
            encoded_password, security_key)
        if user.password_hash != encrypted_password:
            return UserCredentialsError.INVAID_PASSWORD
    elif user.password_security_method == int(MasterPasswordStorageMethod.HASH):
        if not sec.compare_data_encrypted_hash(encoded_password, user.password_hash, user.password_salt, security_key):
            return UserCredentialsError.INVAID_PASSWORD
    else:
        return UserCredentialsError.INVALID_SECURITY_METHOD

    return UserCredentialsError.OK

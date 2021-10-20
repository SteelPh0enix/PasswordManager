from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql.schema import ForeignKey

db_engine = create_engine('sqlite:///app.db', echo=True)
Base = declarative_base()
Session = sessionmaker(bind=db_engine)


class User(Base):
    __tablename__ = 'Users'

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    login = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    pasword_salt = Column(String, nullable=True)
    password_security_method = Column(Integer, nullable=False)

    def __repr__(self) -> str:
        return '<User(id="{0}", login="{1}")>'.format(self.id, self.login)


class PasswordEntry(Base):
    __tablename__ = 'PasswordEntries'

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    password = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('Users.id'), nullable=False)
    login = Column(String)
    web_address = Column(String)
    description = Column(String)

    def __repr__(self) -> str:
        return '<PasswordEntry(id="{0}", user_id="{1}", login="{2}", web_address="{3}", description="{4}")>'.format(
            self.id, self.user_id, self.login, self.web_address, self.description)


Base.metadata.create_all(db_engine)

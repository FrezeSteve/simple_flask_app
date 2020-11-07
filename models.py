from .extensions import db
from datetime import datetime, timedelta
from dateutil import tz
from sqlalchemy import Column, Integer, DateTime, String, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from uuid import uuid4
from werkzeug.security import generate_password_hash


# Accounts

class User(db.Model):
    id = Column(String(40), primary_key=True, unique=True, index=True, nullable=False, default=str(uuid4()))
    username = Column(String(120), unique=True, index=True, nullable=False)
    password = Column(String(120), unique=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)

    admin = Column(Boolean, nullable=False, default=False)
    active = Column(Boolean, nullable=False, default=True)
    authenticated = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime(), default=datetime.utcnow)
    last_login = Column(DateTime(), default=datetime.utcnow)

    token = relationship('Token', uselist=False, backref="auth")

    def __init__(self, username, email, password):
        self.public_id = str(uuid4())
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)

    def __repr__(self):
        return f"User<'{self.username}'>"


# Accounts
class Anonymous(db.Model):
    id = Column(Integer, primary_key=True)
    user_ip = Column(Text, unique=True, index=True, nullable=False)
    private_key = Column(Text, unique=True)
    create_date = Column(DateTime())
    last_login = Column(DateTime(), default=datetime.utcnow, nullable=False)

    def __init__(self, user_ip, private_key):
        self.user_ip = user_ip
        self.private_key = private_key
        self.create_date = datetime.now(tz=tz.tzlocal())

    def __repr__(self):
        return f"<Anonymous '{self.user_ip}'>"


class Token(db.Model):
    id = Column(String(40), primary_key=True, unique=True, index=True, nullable=False, default=str(uuid4()))
    token = Column(Text, unique=True, index=True, nullable=False)
    expiration = Column(DateTime(), default=datetime.utcnow)
    user = Column(String(40), ForeignKey('user.id'), nullable=False)

    def __init__(self, token, user_id):
        self.token = token
        self.expiration = datetime.utcnow() + timedelta(hours=24)
        self.user = user_id

    def __repr__(self):
        return f"<Token '{self.user}'>"

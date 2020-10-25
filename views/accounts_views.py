from .. import models
from ..app import db, app
from ..utils import VerifyToken
from base64 import urlsafe_b64encode, b64encode, b64decode

from cryptography.fernet import Fernet
from cryptography import fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from datetime import timedelta, datetime
from dotenv import load_dotenv, find_dotenv
from flask import Blueprint
from flask import jsonify, request
from flask_restful import Resource, reqparse, Api
import jwt
from os import environ
from re import findall
from uuid import uuid4
from werkzeug.security import check_password_hash

load_dotenv(find_dotenv())


def get_key(password):
    digest = hashes.Hash(hashes.SHA512_256(), backend=default_backend())
    digest.update(password)
    return urlsafe_b64encode(digest.finalize())


encoded_password = environ.get('SECRET_KEY').encode()
key = get_key(encoded_password)
cipher_text = Fernet(key)

accounts = Blueprint('main', __name__)
api = Api(accounts)


class AnonymousView(Resource):
    @staticmethod
    def encode_base64(message):
        message_bytes = message.encode('ascii')
        base64_bytes = b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def get(self):
        ip_address = request.remote_addr
        # generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # serialize the private key for either storage or convert to string
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # encode to base64 private key
        base64_message_private_key = self.encode_base64(private_pem.decode())
        # encode to base64 public key
        base64_message = self.encode_base64(public_pem.decode())
        user_ip_address = models.Anonymous.query.filter_by(user_ip=ip_address).first()
        if user_ip_address:
            user_ip_address.private_key = base64_message_private_key
            db.session.add(user_ip_address)
        else:
            db.session.add(models.Anonymous(ip_address, base64_message_private_key))
        db.session.commit()
        return {'public_key': base64_message}


class CustomEncryption(Resource):
    pass


class Login(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.time_to_exp = timedelta(seconds=59)

    @staticmethod
    def decode_base64(message):
        message_bytes = message.encode('ascii')
        base64_bytes = b64decode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def post(self):
        self.parser.add_argument('login', type=dict, help="login credentials are needed")
        args = self.parser.parse_args()
        login = args['login']
        if login is not None:
            ip_address = request.remote_addr
            user_ip_address = models.Anonymous.query.filter_by(user_ip=ip_address).first()
            if not user_ip_address:
                return {"error": "Unknown User"}, 400

            private_key = self.decode_base64(user_ip_address.private_key)
            private_key = serialization.load_pem_private_key(
                private_key.encode(),
                password=None,
                backend=default_backend()
            )
            try:
                original_message = private_key.decrypt(
                    b64decode(login["email"]),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
                print(original_message)
            except ValueError as e:
                return {'error': "Login Failed"}, 400
            # required fields is email and password
            email = login.get("email", None)
            if email is None or len(email) <= 7:
                return {"error": "email is invalid or empty"}, 400

            if "@" not in email or "." not in email:
                return {"error": "enter a valid email"}, 400
            password = login.get("password", None)
            if password is None or len(password) <= 7:
                return {"error": "Invalid login credentials"}, 401
            qs = models.User.query.filter_by(email=email).first()
            if qs is None:
                return {'error': "Invalid login credentials"}, 401
            elif not qs.active:
                return {'error': "Cannot login. User is not active"}, 401
            elif qs is not None:
                if check_password_hash(qs.password, password):
                    time_exp = datetime.utcnow() + self.time_to_exp
                    token = jwt.encode({'id': qs.id, 'exp': time_exp}, app.config['SECRET_KEY'], 'HS512')
                    # check whether the current user is in the token table
                    qs.last_login = datetime.utcnow()
                    db.session.add(qs)
                    user = qs.token
                    if user is None:
                        # Add the token to the token table
                        db.session.add(models.Token(token.decode('UTF-8'), qs.id))
                        db.session.commit()
                    else:
                        user.token = token.decode('UTF-8')
                        user.expiration = time_exp
                        db.session.commit()
                    encrypted_token = cipher_text.encrypt(token)
                    return {'Token': encrypted_token.decode("UTF-8")}
                else:
                    return {"error": "Invalid login credentials"}, 401
        else:
            return {"error": "Invalid login credentials"}, 401


class Logout(Resource):
    @staticmethod
    def post():
        # verify
        v = VerifyToken(request, cipher_text, fernet, verify_token=False).verify()
        if v:
            return v
        token = request.headers['x-access-token']
        token = cipher_text.decrypt(token.encode())
        data = jwt.decode(token.decode("UTF-8"), app.config['SECRET_KEY'], algorithms=['HS512', 'PS512'])
        user_instance = models.User.query.filter_by(id=data['id']).first()
        if user_instance.token is None:
            return {"error": "User already logged out"}, 401
        elif user_instance.token.token != token.decode("UTF-8"):
            return {"error": "Invalid token"}, 401
        db.session.delete(user_instance.token)
        db.session.commit()
        return {"message": "Successfully logged out"}


class Register(Resource):

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.token = None

    @staticmethod
    def get():
        # verify
        v = VerifyToken(request, cipher_text, fernet, admin=True).verify()
        if v:
            return v

        queryset = models.User.query.all()
        users = []
        for i in queryset:
            data = {"id": i.id, 'username': i.username, 'email': i.email, "is_admin": i.admin}
            users.append(data)
        return jsonify({"users": users})

    def post(self):
        self.parser.add_argument('user', type=dict, help="user is a dictionary object with "
                                                         "required keys ie email, username and password")
        args = self.parser.parse_args()

        # validation
        if args['user'] is None:
            return {"error": "user object is none"}, 400
        user = args['user']
        # check whether the various fields have been received
        if user.get('email', None) is None or user.get('username', None) is None:
            return {"error": "email or username is none"}, 400
        elif user.get('password', None) is None:
            return {"error": "password is none"}, 400
        # check whether the various fields have been entered correctly
        # email has to have an @ symbol and a . symbol
        email = user['email']
        if "@" not in email or "." not in email:
            return {"error": "enter a valid email"}, 400
        # password is at least 4 characters long and contains a capital letter and a symbol
        password = user['password']
        if not len(findall("[A-Za-z0-9@#$%^&+!=]", password)) >= 8:
            return (
                {"error": "password must be at least 8 characters long and"
                          " contains a capital letter and a symbol"}, 400)
        # username dictionary should be there
        username = user['username']
        if len(username) < 1:
            return {"error": "enter a valid username"}, 400
        # username and email should be unique
        if models.User.query.filter_by(username=username).first():
            return {"error": "username already exists"}, 400
        elif models.User.query.filter_by(email=email).first():
            return {"error": "email already exists"}, 400
        # end of validation

        user = models.User(args['user']['username'], args['user']['email'], args['user']['password'])
        if not models.User.query.all():
            user.admin = True
        db.session.add(user)
        db.session.commit()
        return {"user": "{username} was successfully added".format(username=args['user']['username'])}


api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(Register, '/register')
api.add_resource(CustomEncryption, '/encrypt')
api.add_resource(AnonymousView, '/session')

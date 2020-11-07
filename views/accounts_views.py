from .. import models
from ..app import db, app
from ..utils import VerifyToken, get_user_by_ip, get_private_key, decrypt, encode_base64
from base64 import urlsafe_b64encode, b64encode

from cryptography.fernet import Fernet
from cryptography import fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from dateutil import tz
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
        base64_message_private_key = encode_base64(private_pem.decode())
        # encode to base64 public key
        base64_message = encode_base64(public_pem.decode())
        user_ip_address = models.Anonymous.query.filter_by(user_ip=ip_address).first()
        if user_ip_address:
            user_ip_address.private_key = base64_message_private_key
            user_ip_address.last_login = datetime.now(tz=tz.tzlocal())
            db.session.add(user_ip_address)
        else:
            db.session.add(models.Anonymous(ip_address, base64_message_private_key))
        db.session.commit()
        return {'public_key': base64_message}


class CustomEncryption(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()

    def post(self):
        # get the user stored in the database using the ip
        get_user_ = get_user_by_ip(request)
        if not get_user_:
            return {'error': "Login Failed"}, 400
        # get the private key of the user stored in the database
        private_key = get_private_key(get_user_)

        public_key = private_key.public_key()

        json_data = request.get_json()
        if json_data:
            encrypted_data = {}
            for key_, value in json_data.items():
                if isinstance(json_data[key_], str):
                    ciphertext_ = public_key.encrypt(
                        json_data[key_].encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                            algorithm=hashes.SHA1(),
                            label=None
                        )
                    )
                    encrypted_data[key_] = b64encode(ciphertext_).decode('ascii')
            return encrypted_data, 200
        return {}, 202


class GetName(Resource):
    @staticmethod
    def get():
        # verify
        v = VerifyToken(request, cipher_text, fernet, verify_token=False).verify()
        if v:
            return v
        token = cipher_text.decrypt(request.headers['x-access-token'].encode())
        return {}, 200


class Login(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.time_to_exp = timedelta(minutes=5)

    @staticmethod
    def get():
        v = VerifyToken(request, cipher_text, fernet).verify()
        if v:
            return v
        # get the user
        token = request.headers['x-access-token']
        token = cipher_text.decrypt(token.encode())
        data = jwt.decode(token.decode("UTF-8"), app.config['SECRET_KEY'], algorithms=['HS512', 'PS512'])
        user_obj = models.User.query.filter_by(id=data['id']).first()
        if user_obj:
            return {"message": "User exists"}
        else:
            return {"error": "use a valid token"}, 400

    def post(self):
        self.parser.add_argument('login', type=dict, help="login credentials are needed")
        args = self.parser.parse_args()
        login = args['login']
        if login is not None:
            # get the user stored in the database using the ip
            get_user_ = get_user_by_ip(request)
            if not get_user_:
                return {'error': "Login Failed"}, 400
            # get the private key of the user stored in the database
            private_key = get_private_key(get_user_)

            # decrypt the email
            email = decrypt(login.get('email'), private_key)
            if not email:
                return {'error': "Login Failed"}, 400
            # validations
            if len(email) <= 7:
                return {"error": "email is invalid or empty"}, 400
            if "@" not in email or "." not in email:
                return {"error": "enter a valid email"}, 400

            # decrypt the password
            password = decrypt(login.get('password'), private_key)
            if not password:
                return {'error': "Login Failed"}, 400
            # validations
            if len(password) <= 7:
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
        # get the user stored in the database using the ip
        get_user_ = get_user_by_ip(request)
        if not get_user_:
            return {'error': "Login Failed"}, 400
        # get the private key of the user stored in the database
        private_key = get_private_key(get_user_)

        # check whether the various fields have been received
        if user.get('email', None) is None or user.get('username', None) is None:
            return {"error": "email or username is none"}, 400
        elif user.get('password', None) is None:
            return {"error": "password is none"}, 400

        # decrypt the email
        email = decrypt(user['email'], private_key)
        # check whether the various fields have been entered correctly
        # email has to have an @ symbol and a . symbol
        if "@" not in email or "." not in email:
            return {"error": "enter a valid email"}, 400

        # decrypt the password
        password = decrypt(user['password'], private_key)
        # return {"error": "backend testing!!"}, 400
        # password is at least 4 characters long and contains a capital letter and a symbol
        if not len(findall("[A-Za-z0-9@#$%^&+!=]", password)) >= 8:
            return (
                {"error": "password must be at least 8 characters long and"
                          " contains a capital letter and a symbol"}, 400)
        # decrypt the username
        username = decrypt(user['username'], private_key)
        if len(username) < 1:
            return {"error": "enter a valid username"}, 400
        # username and email should be unique
        if models.User.query.filter_by(username=username).first():
            return {"error": "username already exists"}, 400
        elif models.User.query.filter_by(email=email).first():
            return {"error": "email already exists"}, 400
        # end of validation

        user = models.User(username, email, password)
        if not models.User.query.all():
            user.admin = True
        db.session.add(user)
        db.session.commit()
        return {"user": "{username} was successfully added".format(username=args['user']['username'])}


class ValidateToken(Resource):
    @staticmethod
    def post():
        # verify
        v = VerifyToken(request, cipher_text, fernet, verify_token=False).verify()
        if v:
            return v
        return {}, 200


api.add_resource(AnonymousView, '/session')
api.add_resource(CustomEncryption, '/encrypt')
api.add_resource(GetName, '/get_name')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(Register, '/register')
api.add_resource(ValidateToken, '/validate')

from .. import models
from ..app import db, app
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv, find_dotenv
from datetime import timedelta, datetime
from flask import Blueprint
from flask_restful import Resource, reqparse, Api
from flask import jsonify, request
import jwt
from os import environ
from werkzeug.security import check_password_hash
from re import findall


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


class Login(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.time_to_exp = timedelta(minutes=2)

    def post(self):
        self.parser.add_argument('login', type=dict, help="login credentials are needed")
        args = self.parser.parse_args()
        login = args['login']
        if login is not None:
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

# todo: finish logout endpoint
class Logout(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.time_to_exp = timedelta(minutes=2)

    def post(self):
        self.parser.add_argument('login', type=dict, help="login credentials are needed")
        args = self.parser.parse_args()
        login = args['login']
        if login is not None:
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


class Register(Resource):

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.token = None

    def verify(self):
        # verify the access token
        if 'x-access-token' in request.headers:
            self.token = request.headers['x-access-token']
        if self.token is None: return {"error": "permission denied"}, 401
        try:
            self.token = cipher_text.decrypt(self.token.encode())
        except fernet.InvalidToken:
            return {"error": "Invalid Token"}, 401
        try:
            data = jwt.decode(self.token.decode("UTF-8"), app.config['SECRET_KEY'], algorithms=['HS512', 'PS512'])
            # know that the current logged in user is using a token that is in the token table.
            user_obj = models.User.query.filter_by(id=data['id']).first()

            if user_obj.token is None and not user_obj.admin:
                raise Exception("You should login as admin")
            if user_obj.token.token != self.token.decode("UTF-8"):
                raise Exception("login again")
        except jwt.exceptions.DecodeError:
            return {"error": "Invalid Token"}, 401
        except jwt.exceptions.ExpiredSignatureError:
            return {"error": "Invalid Token"}, 401
        except Exception as e:
            return {"error": "Token is invalid, {}".format(e)}, 401
        return False

    def get(self):
        # verify
        v = self.verify()
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
api.add_resource(Register, '/register')

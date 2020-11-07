from .models import User, Anonymous
from .app import app
from base64 import b64decode, b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import jwt


class VerifyToken:
    def __init__(self, request, cipher_text, fernet, admin=False, verify_token=True):
        self.request = request
        self.cipher_text = cipher_text
        self.fernet = fernet
        self.admin = admin
        self.verify_token = verify_token

    def verify(self):
        token = None
        # verify the access token
        if 'x-access-token' in self.request.headers:
            token = self.request.headers['x-access-token']
        if token is None: return {"error": "permission denied"}, 401
        try:
            token = self.cipher_text.decrypt(token.encode())
        except self.fernet.InvalidToken:
            return {"error": "Invalid Token"}, 401
        try:
            data = jwt.decode(token.decode("UTF-8"), app.config['SECRET_KEY'], algorithms=['HS512', 'PS512'])
            # know that the current logged in user is using a token that is in the token table.
            user_obj = User.query.filter_by(id=data['id']).first()
            if self.verify_token:
                if user_obj.token is None:
                    raise Exception("Cannot be verified")
                if self.admin and (not user_obj.admin):
                    raise Exception("You should login as admin")
                if user_obj.token.token != token.decode("UTF-8"):
                    raise Exception("Cannot be identified")
        except jwt.exceptions.DecodeError:
            return {"error": "Invalid Token"}, 401
        except jwt.exceptions.ExpiredSignatureError:
            return {"error": "Invalid Token: Expired Token"}, 401
        except Exception as e:
            return {"error": "Token is invalid, {}".format(e)}, 401
        return False


def get_user_by_ip(request_):
    ip_address = request_.remote_addr
    user_ip_address = Anonymous.query.filter_by(user_ip=ip_address).first()
    if not user_ip_address:
        return None
    return user_ip_address


def decode_base64(message):
    message_bytes = message.encode('ascii')
    base64_bytes = b64decode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


def encode_base64(message):
    message_bytes = message.encode('ascii')
    base64_bytes = b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


def get_private_key(get_user_):
    private_key = decode_base64(get_user_.private_key)
    private_key = serialization.load_pem_private_key(
        private_key.encode(),
        password=None,
        backend=default_backend()
    )
    return private_key


def decrypt(message, private_key):
    try:
        original_message = private_key.decrypt(
            b64decode(message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
    except ValueError:
        return None
    return original_message.decode()

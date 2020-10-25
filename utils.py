from .models import User
from .app import app
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

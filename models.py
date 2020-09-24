from extensions import db
from uuid import uuid4


class User(db.Model):
    id = db.Column(db.String(40), primary_key=True, default=str(uuid4()))
    name = db.Column(db.String(128))

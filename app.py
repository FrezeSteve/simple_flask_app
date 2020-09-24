from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from uuid import uuid4

load_dotenv()

app = Flask(__name__)

base_folder = os.path.split(os.path.abspath(__file__))[0]
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = int(os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.String(40), primary_key=True, default=str(uuid4()))
    name = db.Column(db.String(128))

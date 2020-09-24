from dotenv import load_dotenv
from flask import Flask
from .extensions import db
from . import views
import os

load_dotenv()

app = Flask(__name__)

base_folder = os.path.split(os.path.abspath(__file__))[0]
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = int(os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')

db.init_app(app)

app.register_blueprint(views.main)

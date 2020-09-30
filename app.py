from .extensions import db
from dotenv import load_dotenv
from flask import Flask
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
import os

load_dotenv()

app = Flask(__name__)

base_folder = os.path.split(os.path.abspath(__file__))[0]
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = int(os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')

db.init_app(app)

migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

from . import views

app.register_blueprint(views.accounts)


if __name__ == "__main__":
    app.run()

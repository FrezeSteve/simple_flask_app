from flask import Blueprint
from .models import User

main = Blueprint('main', __name__)


@main.route('/')
def login():
    return 'Hello, World!'

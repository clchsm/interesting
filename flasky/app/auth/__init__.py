from flask import Blueprint
from app import login_manager

auth = Blueprint('auth', __name__)
login_manager.login_view='auth.login'

from . import views

from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_ckeditor import CKEditor
from flask_mail import Mail
from datetime import timedelta
from flask_dropzone import Dropzone
from flask_wtf.csrf import CSRFProtect
from flask_whooshee import Whooshee

from .config import config

bootstrap = Bootstrap()
db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()
ckeditor = CKEditor()
mail = Mail()
dropzone = Dropzone()
csrf = CSRFProtect()
whooshee = Whooshee()

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    bootstrap.init_app(app)
    db.init_app(app)
    socketio.init_app(app)
    login_manager.init_app(app)
    ckeditor.init_app(app)
    mail.init_app(app)
    dropzone.init_app(app)
    csrf.init_app(app)
    whooshee.init_app(app)

    app.permanent_session_lifetime = timedelta(hours=24)
    
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix = '/auth')
    
    return app

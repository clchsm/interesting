import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY= os.environ.get('SECRET_KEY') or "12345678"
    #数据库mysql及sqlalchemy设置
    USERNAME = os.environ.get('DBUSERNAME')
    PASSWORD = os.environ.get('PASSWORD')
    HOSTNAME = os.environ.get('HOSTNAME')
    DATABASE = os.environ.get('DATABASE')
    TESTBASE = os.environ.get('TESTBASE') 
    PRODUCTBASE = os.environ.get('PRODUCTBASE')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    #ckeditor设置
    CKEDITOR_SERVE_LOCAL = True
    CKEDITOR_HEIGHT = 200
    CKEDITOR_WIDTH = 500
    allowedContent = False

    #邮箱设置
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = 465 #25
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    FLASK_ADMIN = os.environ.get('FLASK_ADMIN') or '614566327@qq.com'
    FLASKY_MAIL_SENDER = 'Flask Admin <614566327@qq.com>'
    FLASKY_MAIL_SUBJECT_PREFIX = '你的邮件'

    WHOOSHEE_MIN_STRING_LEN = 1
    WHOOSHEE_MEMORY_SOTRAGE = True
    
    #dropzone设置
    DROPZONE_MAX_FILE_SIZE = 5
    DROPZONE_MAX_FILES = 8
    DROPZONE_ALLOWED_FILE_TYPE = 'image'
    DROPZONE_DEFAULT_MESSAGE = "点此上传文件"
    DROPZONE_ENABLE_CSRF = True
    DROPZONE_UPLOAD_ON_CLICK = True
    DROPZONE_REDIRECT_VIEW = 'main.complated'
    
    MAX_CONTENT_LENGTH = 3*1024*1024

    APP_UPLOAD_PATH = os.path.join(basedir, 'uploads')
    APP_PHOTO_SIZE = {'small':200, 'medium':800}
    APP_PHOTO_SUFFIX = {
        APP_PHOTO_SIZE['small']:'_s',
        APP_PHOTO_SIZE['medium']:'_m'
    }
    
    FLASKY_POST_PER_PAGE=10
    FLASKY_IMAGEPOST_PER_PAGE=5
    FLASKY_USER_PER_PAGE = 20
    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI ='mysql://'+ Config.USERNAME +':'+ Config.PASSWORD +'@' + Config.HOSTNAME+'/'+ Config.DATABASE


class TestingConfig(Config):
    DEBUG=True
    SQLALCHEMY_DATABASE_URI='mysql://'+'mysql://'+ Config.USERNAME +':'+ Config.PASSWORD +'@' + Config.HOSTNAME+'/'+ Config.TESTBASE
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DEBUG=True
    SQLALCHEMY_DATABASE_URI='mysql://'+'mysql://'+ Config.USERNAME +':'+ Config.PASSWORD +'@' + Config.HOSTNAME+'/'+ Config.PRODUCTBASE
    
config = {
    'development':DevelopmentConfig,
    'testing':TestingConfig,
    'production':ProductionConfig,
    'default':DevelopmentConfig
}

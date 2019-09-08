import os
from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.mysql import LONGTEXT
from markdown import markdown
import bleach

from app import db, whooshee
from . import login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    ADMINISTRATOR = 8


class FriendRequest(db.Model):
    __tablename__ = 'friendrequests'
    from_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    to_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    validation = db.Column(db.String(256))
    time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)


roomregisters = db.Table('roomregisters',
                         db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
                         db.Column('room_id', db.Integer, db.ForeignKey('rooms.id')))


collections = db.Table('collections',
                       db.Column('collector_id', db.Integer, db.ForeignKey('users.id')),
                       db.Column('item_id', db.Integer, db.ForeignKey('imageposts.id')))


class Friendship(db.Model):
    __tablename__ = 'friendships'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    
    
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, default=None)
    data = db.Column(db.Text)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, default=None)
    state = db.Column(db.String(16),default=True, nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=True, default=None)
    time_stamp = db.Column(db.DateTime, index=True)
    

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def add_permission(self, permission):
        if not self.has_permission(permission):
            self.permissions += permission

    def remove_permissions(self, permission):
        if self.has_permission(permission):
            self.permissions -= permission

    def reset_permission(self):
        self.permissions = 0

    def has_permission(self, permission):
        return self.permissions & permission == permission
    
    @staticmethod
    def insert_roles():
        roles = {
            'User':[Permission.FOLLOW, Permission.WRITE, Permission.COMMENT],
            'Administrator':[Permission.FOLLOW, Permission.WRITE, Permission.COMMENT, Permission.ADMINISTRATOR],
        }
        default_role = 'User' 
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permission()
            for perm in roles[r]:
                role.add_permission(perm)
                role.default = (role.name == default_role)
                db.session.add(role)
        db.session.commit()
    

@whooshee.register_model('nickname')
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(64), index=True, unique=True, nullable=False)
    name = db.Column(db.String(64), index=True, nullable=False)
    gender = db.Column(db.String(32), nullable=False)
    ID_num = db.Column(db.String(64), nullable=False, unique=True)
    email = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all')
    comments = db.relationship('Comment', backref='author',cascade='all', lazy='dynamic')
    replyed = db.relationship('Reply', backref='replyed_to', cascade='all', lazy='dynamic')
    time_stamp = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    state = db.Column(db.Boolean, default=False)
    session_id = db.Column(db.String(128), default=None)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default=False)
    imageposts = db.relationship('ImagePost', backref='author', lazy="dynamic", cascade='all')
    attentions = db.relationship('Attention', backref='receiver', lazy='dynamic', cascade='all')
    views = db.relationship('View', backref='author', lazy='dynamic', cascade='all')
    send_msgs = db.relationship('Message',
                                foreign_keys=[Message.sender_id],
                                backref=db.backref('sender', lazy='joined'),
                                lazy='dynamic',
                                cascade="all, delete-orphan")
    receive_msgs = db.relationship('Message',
                                   foreign_keys=[Message.receiver_id],
                                   backref=db.backref('receiver', lazy='joined'),
                                   lazy='dynamic',
                                   cascade="all, delete-orphan")
    requests=db.relationship('FriendRequest',
                             foreign_keys=[FriendRequest.from_id],
                             backref=db.backref('request', lazy='joined'),
                             lazy='dynamic',
                             cascade='all, delete-orphan')
    requested=db.relationship('FriendRequest',
                              foreign_keys=[FriendRequest.to_id],
                              backref=db.backref('requested', lazy='joined'),
                              lazy='dynamic',
                              cascade='all, delete-orphan')
    relations = db.relationship('Friendship',
                                foreign_keys=[Friendship.user_id],
                                backref=db.backref('user', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    friends = db.relationship('Friendship',
                              foreign_keys=[Friendship.friend_id],
                              backref=db.backref('friend', lazy='joined'),
                              lazy='dynamic',
                              cascade='all, delete-orphan')
    rooms = db.relationship('Room',
                            secondary=roomregisters,
                            backref = db.backref('users', lazy='dynamic'),
                            lazy='dynamic')
    collections = db.relationship('ImagePost',
                                  secondary=collections,
                                  backref=db.backref('collectors', lazy='dynamic'),
                                  lazy='dynamic')
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASK_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if not self.is_friend(self):
            self.add_friend(self)
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def request(self, user):
        if not self.is_requesting(user):
            f = FriendRequest(request=self, requested=user)
            db.session.add(f)

    def request_sent(self, user):
        if user.id is None:
            return False
        return self.requests.filter_by(to_id=user.id).first() is not None

    def is_requested_by(self, user):
        if user.id is None:
            return False
        return self.requested.filter_by(from_id=user.id).first() is not None

    def add_friend(self, user):
        if user.request_sent(self) and not self.is_friend(user):
            f1 = Friendship(user_id=self.id, friend_id=user.id)
            f2 = Friendship(user_id=user.id, friend_id=self.id)
            if self == user :
                db.session.add(f1)
            else:
                db.session.add(f1)
                db.session.add(f2)
                request = self.requested.filter_by(from_id=user.id).first()
                db.session.delete(request)
            return True
        return False

    def delete_friend(self, user):
        if self.is_friend(user):
            f1 = Friendship.query.filter(Friendship.user_id==self.id, Friendship.friend_id==user.id).first()
            f2 = Friendship.query.filter(Friendship.user_id==user.id, Friendship.friend_id==self.id).first()
            db.session.delete(f1)
            db.session.delete(f2)
            return True
        return False

    def is_friend(self, user):
        if user.id is None:
            return False
        return self.relations.filter_by(friend_id=user.id).first() is not None

    def get_friends(self):
        if self.relations.all():
            for relation in self.relations.all():
                yield relation.friend
        return False
    
    def can(self, permission):
        return self.role is not None and (self.role.permissions & permission)==permission

    def is_administrator(self):
        return self.can(Permission.ADMINISTRATOR)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm':self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True
            

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


@whooshee.register_model('title', 'body')
class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64), nullable=False)
    body = db.Column(LONGTEXT)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    state = db.Column(db.Boolean, default=True, nullable=False)
    time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    comments = db.relationship('Comment', backref='post', cascade='all', lazy='dynamic')

    
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body=db.Column(db.Text)
    state = db.Column(db.Boolean, default=True, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    replys = db.relationship('Reply', backref='comment', lazy='dynamic', cascade='all')
    time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)


class Reply(db.Model):
    __tablename__ = 'replys'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    replyer = db.Column(db.String(64), nullable=False)
    state = db.Column(db.Boolean, default=True, nullable=False)
    time_stamp = db.Column(db.DateTime, index = True, default=datetime.utcnow)
    
    
class Photo(db.Model):
    __tablename__ = 'photos'
    id = db.Column(db.Integer, primary_key=True)
    imagepost_id = db.Column(db.Integer, db.ForeignKey('imageposts.id'), nullable=False)
    filename = db.Column(db.String(64))
    filename_s = db.Column(db.String(64))
    filename_m = db.Column(db.String(64))
    time_stamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@db.event.listens_for(Photo, 'after_delete', named=True)
def delete_photos(**kwargs):
    target = kwargs['target']
    for filename in [target.filename, target.filename_m, target.filename_s]:
        if filename is not None:
            path = os.path.join(current_app.config['APP_UPLOAD_PATH']+'/'+str(target.author_id), filename)
            if os.path.exists(path):
                os.remove(path)
    

@whooshee.register_model('content')
class ImagePost(db.Model):
    __tablename__ = 'imageposts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(256))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    time_stamp = db.Column(db.DateTime, default=datetime.utcnow)
    photos = db.relationship('Photo', backref = 'description', lazy = 'dynamic', cascade='all')
    views = db.relationship('View', backref = 'imagepost', lazy='dynamic', cascade='all')


class View(db.Model):
    __tablename__ = 'views'
    id = db.Column(db.Integer, primary_key=True)
    imagepost_id = db.Column(db.Integer, db.ForeignKey('imageposts.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    view = db.Column(db.String(150))
    time_stamp = db.Column(db.DateTime, default=datetime.utcnow)
    

class Attention(db.Model):
    __tablename__ = 'attentions'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(256))
    url = db.Column(db.String(128))
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    time_stamp = db.Column(db.DateTime, default = datetime.utcnow)


class Room(db.Model):
    __tablename__ = "rooms"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    creater_id = db.Column(db.Integer, nullable=False)
    messages = db.relationship('Message', backref='room', cascade='all', lazy='dynamic')
    description = db.Column(db.String(128))
    time_stamp = db.Column(db.DateTime, default=datetime.utcnow)

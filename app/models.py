from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for
from markdown import markdown
import hashlib
import bleach

from . import db, login_manager
from app.exceptions import ValidationError


class AnoymousUser(AnonymousUserMixin):
    def can(self, permission):
        return False

    def is_adminstrator(self):
        return False


login_manager.anonymous_user = AnoymousUser


@login_manager.user_loader
def load_user(user_id):
    # login_manager.user_loader 装饰器把这个函数注册给Flask-login,在这个扩展需要获取已登录用户的信息时调用
    return User.query.get(int(user_id))


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Follow(db.Model):
    # 关联表单 用来记录 关注者和被关注者
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    # 添加认证属性 并且设置默认为False
    confirmed = db.Column(db.Boolean, default=False)
    # 添加用户其他信息
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    # 存储头像的链接md5值
    avator_hash = db.Column(db.String(32))
    # 关联文章外建
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    # 关注信息
    # 为了消除外建间的歧义，定义关系时必须使用可选参数 foreign_keys 指定外建
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),  # joined 参数实现立即从联结查询中加载相关对象
                               lazy='dynamic',
                               cascade='all,delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all,delete-orphan')
    # 关联评论
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.avator_hash is None and self.email is not None:
            self.avator_hash = self.gravatar_hash()
        self.follow(self)

    def __repr__(self):
        return '<User : %r>' % self.username

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        # 将用户需要设置的密码加密
        self.password_hash = generate_password_hash(password=password)

    def verify_password(self, password):
        # 验证密码是否正确
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        # 返回确认令牌加密过得id值
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirmed': self.id}).decode('utf-8')

    def generate_email_token(self, new_email, expirtaion=3600):
        # 返回确认令牌加密过得id和email值
        s = Serializer(current_app.config['SECRET_KEY'], expirtaion)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def generate_password_token(self, expirtaion=3600):
        # 返回确认令牌加密过得id和password值
        s = Serializer(current_app.config['SECRET_KEY'], expirtaion)
        return s.dumps({'reset': self.id, })

    def confirm(self, token):
        # 返回确认令牌解密过得id值
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # 尝试获取token中的信息
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirmed') != self.id:
            # 尝试获取token中的confirmed信息
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def confirm_email(self, token):
        # 返回确认令牌解密过得id值
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # 尝试获取token中的信息
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('change_email') != self.id:
            # 尝试获取token中的confirmed信息
            return False
        self.email = data.get('new_email')
        self.avator_hash = self.gravatar_hash()
        db.session.add(self)
        return True

    @staticmethod
    def confirm_password(token, new_password):
        # 返回确认令牌解密过得id值
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # 尝试获取token中的信息
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def can(self, perm):
        # 判断该用户的角色是否有某权限
        return self.role.has_permission(perm) and self.role is not None

    def is_administrator(self):
        # 判断该用户是否是管理员
        return self.can(Permission.ADMIN)

    def ping(self):
        # 更新最后登录时间
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def gravatar(self, size=100, default='identicon', rating='g'):
        # 获取头像链接
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'https://www.gravatar.com/avatar'
        hash = self.avator_hash or self.gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def gravatar_hash(self):
        # 返回头像md5值
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def follow(self, user):
        # 关注
        if not self.is_following(user):
            #                    ->
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        # 取消关注
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        # 判断是否时当前用户的关注者
        if user is None:
            return False
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed(self, user):
        # 判断当前用户是否关注了他
        if user is None:
            return False
        return self.followers.filter_by(followed_id=user.id).first() is not None

    @property
    def followed_posts(self):
        # 显示所关注用户的文章
        return Post.query.join(Follow, Follow.followed_id == Post.author_id).filter(Follow.followed_id == self.id)

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                print('a')
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def generate_auth_token(self, expiration):
        # 生成签名令牌
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id}).decode('utf-8')

    @staticmethod
    def verify_auth_token(token):
        # 解析签名令牌
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def to_json(self):
        # 将用户转化为json格式的序列化字典
        json_user = {
            'url': url_for('api.get_user', id=self.id),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts_url': url_for('api.get_user_posts', id=self.id),
            'followed_posts_url': url_for('api.get_user_followed_posts',
                                          id=self.id),
            'post_count': self.posts.count()
        }
        return json_user


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    users = db.relationship('User', backref='role', lazy='dynamic')
    # 添加权限属性值
    default = db.Column(db.Boolean, default=False, index=True)
    permission = db.Column(db.Integer)

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permission is None:
            self.permission = 0

    def __repr__(self):
        return '<Role : %r>' % self.name

    def add_permission(self, prem):
        if not self.has_permission(prem):
            self.permission += prem

    def has_permission(self, prem):
        return self.permission & prem == prem

    def remove_permission(self, prem):
        if self.has_permission(prem):
            self.permission -= prem

    def reset_permission(self):
        self.permission = 0

    @staticmethod
    def insert_roles():
        # 创建三个角色并添加相关权限
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT,
                              Permission.WRITE, Permission.MODERATE,
                              Permission.ADMIN],
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


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # 保存博客内容 单独上传 以避免表单上传时丢预览数据的情况
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    # 关联评论
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(  # 把纯文本中的url 转换成合适的<a>链接
            bleach.clean(  # 删除所有不再白名单的标签
                markdown(value, output_format='html'), tags=allowed_tags))  # markdown方法将文本转换成HTML
        # 设置监听 只要body字段设了新值，这个函数就会自动被调用
        db.event.listen(Post.body, 'set', Post.on_changed_body)

    def to_json(self):
        # 把文章转换成json格式的序列化字典
        json_post = {
            'url': url_for('api.get_post', id=self.id),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author_url': url_for('api.get_user', id=self.author_id),
            'comments_url': url_for('api.get_post_comments', id=self.id),
            'comment_count': self.comments.count()
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        # 从json格式数据中创建一篇博客文章
        body = json_post.get('body')
        if body is None or body == '':
            raise ValidationError('post does not have a body')
        return Post(body=body)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i', 'strong']
        target.body_html = bleach.linkify(
            bleach.clean(markdown(value, output_format='html'), tags=allowed_tags, strip=True))


db.event.listen(Comment.body, 'set', Comment.on_changed_body)

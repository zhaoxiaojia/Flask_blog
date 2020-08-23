from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError
from flask_pagedown.fields import PageDownField

from ..models import Role, User


class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')


class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField("About me")
    submit = SubmitField('Submit')


class EditProfileAdminForm(EditProfileForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
        DataRequired(),
        Length(1, 64),
        Regexp('^[A-Za-z0-9][A-Za-z0-9_.]*$', 0, 'Username must have only letters,numbers,dots or underscores')
    ])
    confimed = BooleanField('Confirmed')
    role = IntegerField('Role', coerce=int)  # coerce = int 把字段的值转换成整数
    submit = SubmitField('Submit')

    def __init__(self, user, **kwargs):
        super(EditProfileAdminForm, self).__init__(**kwargs)
        # 定义role 选项
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        # 判断输入的邮箱是否已经注册
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        # 判断输入的用户名是否已经使用
        if field.data != self.user.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class PostForm(FlaskForm):
    body = PageDownField("What's on your mind", validators=[DataRequired()])
    submit = SubmitField('Submit')


class CommentForm(FlaskForm):
    body = PageDownField('', validators=[DataRequired()])
    submit = SubmitField('Submit')

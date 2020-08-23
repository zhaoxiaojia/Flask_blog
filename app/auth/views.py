from flask import render_template, request, url_for, redirect, flash
from flask_login import login_user, login_required, logout_user, current_user

from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationFrom, ChangePasswordForm, ChangeEmailForm, PasswordResetRequestForm


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid username or password')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationFrom()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email,
                   'Confirm Your account',
                   'auth/email/confirm',
                   user=user, token=token)
        flash('A confirmation email has been send to you by email')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    # 判断此账户是否已经确认过
    if current_user.confirmed:
        return redirect('main.index')
    # 确认token中的id信息
    if current_user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confimed link is invalid or has expired.')
    return redirect(url_for('main.index'))


# 被该装饰器装饰的方法都会在请求前被调用 针对全局路由使用 before_request 针对当前蓝本
@auth.before_app_request
def before_request():
    # 判断在 用于已登录 用户未确认 访问非auth且非静态时 跳转至页面确认页面
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.blueprint != 'auth' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.uncofirmed'))


@auth.route('/uncofirmed')
def uncofirmed():
    # 判断用户非登录或者已确认时 跳转到首页
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/uncomfirmed.html')


@auth.route('/resend_confirmation')
@login_required
def resend_confirmation():
    # 重新发送确认邮件
    token = current_user.generate_confirmation_token()
    send_email(current_user.email,
               'Confirm Your account',
               '/auth/email/confirm',
               user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template("auth/change_password.html", form=form)


@auth.route('/change_email_request', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        token = current_user.generate_email_token(form.email.data)
        send_email(
            form.email.data,
            'Change your email address',
            'auth/email/change_email',
            user=current_user, token=token
        )
        flash('An email with instruction to confirm your new email address has been sent to your new email address')
        return redirect(url_for('main.index'))
    return render_template('auth/change_email.html', form=form)


@auth.route('/change_email/<token>', methods=['GET', 'POST'])
@login_required
def change_email(token):
    # 确认token中的id信息
    if current_user.confirm_email(token=token):
        db.session.commit()
        flash('You have confirmed your email. Thanks!')
    else:
        flash('The confimed link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_password_token()
            send_email(
                form.email.data,
                'Reset your password',
                'auth/email/reset_password',
                user=user, token=token, next=request.args.get('next')
            )
        flash('An email with instruction to confirm your new password has been sent to your email address')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    # 确认token中的id信息
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if User.confirm_password(token, form.password.data):
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)

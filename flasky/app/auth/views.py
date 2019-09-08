from flask import render_template, request, flash, url_for, redirect, render_template
from flask_login import login_required, login_user, logout_user, current_user

from .forms import LoginForm, RegisterForm, UserProfileForm, ForgetPasswordForm, ChangePasswordForm, ConfirmForm, AdminProfileForm
from app import db
from app.models import User
from app.decorators import admin_required
from . import auth
from ..async import send_mail


@auth.route('/login', methods = ['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        flash('您已登录，不必重复登录！')
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(nickname=form.nickname.data).first()
        if user is not None:
            if user.verify_password(form.password.data):
                login_user(user, 1)
                user.state=True
                db.session.add(user)
                db.session.commit()
                return redirect(request.args.get('next', url_for('main.index')))
        flash(u'不存在此用户.')
    return render_template('auth/login.html', form=form)


@auth.route('/forget-password', methods=['GET', 'POST'])
def forget_password():
    form = ForgetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user.nickname == form.nickname.data and user.ID_num == form.ID_num.data:
            if user.verify_password(form.password.data):
                flash('密码并未改变！')
                return redirect(url_for('auth.login'))
            user.password = form.password.data
            user.confirmed = False
            token = user.generate_confirmation_token()
            send_mail(user.email, '更改密码', 'auth/email/confirm', user=user, token=token)
            db.session.add(user)
            db.session.commit()
            flash('已重新向您的邮箱发送了确认邮件，请前往确认！')
            return redirect(url_for('auth.login'))
        flash ('邮箱，昵称及ID号不匹配！')
    return render_template('auth/forget_password.html', form=form)


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if not current_user.is_authenticated:
        flash('您还未登录！')
        next = request.referrer
        if next is None or not next.startswith('/'):
            next = url_for('auth.login')
        return redirect(next)
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.password = form.password.data
        current_user.confirmed = False
        db.session.add(current_user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_mail(user.email, '确认密码', 'auth/email/confirm', user=user, token=token)
        login_user(user, 1)
        next = request.args.get('next')
        if next is None or not next.startswith('/'):
            next = url_for('main.index')
        return redirect(next)
    return render_template('auth/change_password.html', form=form)    


@auth.route('/register', methods = ['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(nickname=form.nickname.data,
                    name=form.name.data,
                    gender=form.gender.data,
                    password=form.password.data,
                    ID_num=form.ID_num.data,
                    email=form.email.data,
                    state=True)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_mail(user.email, '确认账户', 'auth/email/confirm', user=user, token=token)
        login_user(user, 1)
        next = request.args.get('next')
        if next is None or not next.startswith('/'):
            next = url_for('main.index')
        return redirect(next)
    return render_template('auth/register.html', form=form)    


@auth.route('/edit-profile/<id>', methods = ['GET','POST'])
@login_required
def edit_profile(id):
    user = User.query.filter_by(id=id).first()
    profileform = UserProfileForm()
    if user is None:
        return redirect(url_for('main.index'))
    if current_user != user:
        flash('您不是此用户，不可编辑其信息！')
        return redirect(url_for('main.index'))
    if profileform.validate_on_submit():
        user.nickname = profileform.nickname.data
        user.gender = profileform.gender.data
        user.email = profileform.email.data
        db.session.add(user)
        db.session.commit()
        login_user(user, 1)
        next = request.args.get('next')
        if next is None or not next.startswith('/'):
            next = url_for('main.index')
        return redirect(next)
    profileform.nickname.data = user.nickname
    profileform.gender.data = user.gender
    profileform.email.data = user.email
    return render_template('auth/edit_profile.html', form=profileform)


@auth.route('/edit-profile-admin/<id>', methods = ['GET','POST'])
@admin_required
@login_required
def edit_profile_admin(id):
    user = User.query.filter_by(id=id).first()
    profileform = AdminProfileForm()
    if user is None:
        return redirect(url_for('.index'))
    if not current_user.is_administrator():
        flash('您不是管理员，不可编辑此信息！')
        return redirect(url_for('.index'))
    if profileform.validate_on_submit():
        user.name = profileform.name.data
        user.ID_num = profileform.ID_num.data
        db.session.add(user)
        db.session.commit()
        next = request.referrer
        if next is None or not next.startswith('/'):
            next = url_for('.index')
        return redirect(next)
    profileform.name.data = user.name
    profileform.ID_num.data = user.ID_num
    return render_template('edit_profile.html', form=profileform)


@auth.route('/confirm/<token>', methods=['GET'])
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('您已确认账户！')
    else:
        flash('链接不可用，请重新确认账户')
    return redirect(url_for('main.index'))
    #return render_template('auth/email/confirm'+'.txt', user=current_user, token=token)


@auth.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed and request.blueprint!='auth' and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/reconfirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_mail(current_user.email, '确认账户', 'auth/email/confirm', user=current_user, token=token)
    flash('已向您的邮箱新发送了一封确认邮件，请登录邮箱确认您的账户。')
    return redirect(url_for('main.index'))


@auth.route('/logout')
@login_required
def logout():
    current_user.state = False
    current_user.session_id=None
    db.session.add(current_user)
    db.session.commit()
    logout_user()
    flash('您已经退出登录.')
    return redirect(url_for('main.index'))
    

@auth.route('/logoff', methods=['GET', 'POST'])
@login_required
def logoff():
    form = ConfirmForm()
    if form.validate_on_submit():
        if form.submit_yes.data:
            db.session.delete(current_user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        elif form.submit_no.data:
            return redirect(url_for('main.index'))
    return render_template('auth/logoff.html', form=form)

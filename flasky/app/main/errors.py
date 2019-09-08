from . import main

@main.route('/error')
@main.errorhandler(401)
def error(e):
    app.logger.debug("error occurred:%s" % e)
    try:
        code = e.code
        if code == 401:
            flash("您需要重新登录.")
    except Exception as e:
        app.logger.debug('exception is %s' % e)
    finally:
        form = LoginForm()
        form.nickname.data = current_user.nickname
        logout_user()
        return render_template('auth/login.html', form=form)

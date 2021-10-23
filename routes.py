from flask import render_template, request, redirect, url_for, flash
from forms import LoginForm, RegistrationForm
from app import app
import actions


@app.route('/', methods=['GET'])
def homepage():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        register_result = actions.register_user(
            form.username.data, form.password.data, int(form.password_storage_method.data))

        if register_result == actions.RegisterError.OK:
            flash('Registration successfull!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration error: {0}!'.format(register_result), 'alert')
            return render_template('register.jhtml', form=form)
    return render_template('register.jhtml', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        login_result = actions.check_user_credentials(form.username.data, form.password.data)

        if login_result == actions.UserCredentialsError.OK:
            flash('Login successfull!', 'success')
            return redirect(url_for('password_manager'))
        else:
            flash('Login error: {0}!'.format(login_result), 'alert')
            return render_template('login.jhtml', form=form)
    return render_template('login.jhtml', form=form)


@app.route('/password_manager', methods=['GET'])
def password_manager():
    return render_template('manager.jhtml', message_box='Hello!')

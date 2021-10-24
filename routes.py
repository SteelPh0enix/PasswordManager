from flask import render_template, request, redirect, url_for, flash
from flask_login.utils import login_required, logout_user
from forms import LoginForm, RegistrationForm, PasswordEntryForm
from app import app
import actions
from flask_login import login_user


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
        login_result, logged_user = actions.check_user_credentials(
            form.username.data, form.password.data)

        if login_result == actions.UserCredentialsError.OK:
            login_user(logged_user)
            flash('Login successfull!', 'success')
            return redirect(url_for('password_manager'))
        else:
            flash('Login error: {0}!'.format(login_result), 'alert')
    return render_template('login.jhtml', form=form)


@app.route('/password_manager', methods=['GET'])
@login_required
def password_manager():
    form = PasswordEntryForm(request.form)
    if request.method == 'POST' and form.validate():
        pass
    return render_template('manager.jhtml', form=form)

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    pass

@app.route('/remove_password', methods=['POST'])
@login_required
def remove_password():
    pass

@app.route('/modify_password', methods=['POST'])
@login_required
def modify_password():
    pass

@app.route('/change_user_password', methods=['POST'])
@login_required
def change_user_password():
    pass
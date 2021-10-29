from flask import render_template, request, redirect, sessions, url_for, flash
from flask_login.utils import login_required, logout_user
from database import PasswordEntry, db
from forms import ChangePasswordForm, LoginForm, RegistrationForm, PasswordEntryForm
from app import app
import actions
from flask_login import login_user, current_user


@app.route('/', methods=['GET'])
def homepage():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('password_manager'))

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
    if current_user.is_authenticated:
        return redirect(url_for('password_manager'))

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
    password_list = PasswordEntry.query.filter_by(user_id=current_user.id)
    if password_list.first() is None:
        password_list = None
    form = PasswordEntryForm(request.form)
    return render_template('manager.jhtml', form=form, password_list=password_list)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    form = PasswordEntryForm(request.form)
    if form.validate():
        actions.add_wallet_password_entry(
            current_user,
            form.title.data,
            form.password.data,
            form.login.data,
            form.web_address.data,
            form.description.data
        )

    return redirect(url_for('password_manager'))


@app.route('/remove_password', methods=['GET'])
@login_required
def remove_password():
    password_id = request.args.get('id')
    try:
        id_validated = int(password_id)
    except ValueError:
        flash('Invalid ID!', 'alert')
        return redirect(url_for('password_manager'))

    password_entry = PasswordEntry.query.filter_by(
        id=id_validated, user_id=current_user.id).first()

    if password_entry is not None:
        db.session.delete(password_entry)
        db.session.commit()
        flash('Password deleted!', 'success')
    else:
        flash('Password doesn\'t exist!', 'alert')

    return redirect(url_for('password_manager'))


@app.route('/get_password', methods=['GET'])
@login_required
def get_password():
    password_id = request.args.get('id')

    try:
        id_validated = int(password_id)
    except ValueError:
        flash('Invalid ID!', 'alert')
        return redirect(url_for('password_manager'))

    password_entry = PasswordEntry.query.filter_by(
        id=id_validated, user_id=current_user.id).first()

    # Decrypt the password
    if password_entry is not None:
        decrypted_password = actions.get_wallet_password_entry(
            current_user, password_id)
        return {'status': 'ok', 'data': decrypted_password.decode('UTF-8')}
    return {'status': 'error'}


@app.route('/change_user_password', methods=['GET', 'POST'])
@login_required
def change_user_password():
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        if actions.change_user_password(current_user.id, form.old_password.data, form.new_password.data):
            flash('Password changed successfully, log in again!', 'success')
            return redirect(url_for('logout'))
        else:
            flash('Couldn\'t change the password! Check if the old password is correct and try again!', 'alert')
    
    return render_template('change_password.jhtml', form=form)
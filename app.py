from flask import Flask, render_template, request, flash, redirect, url_for
from forms import LoginForm, MasterPasswordStorageMethod, RegistrationForm
from dotenv import dotenv_values
from database import Session

ENV_VARS = dotenv_values('.env')

app = Flask(__name__,
            static_url_path='',
            static_folder='static',
            template_folder='templates')


@app.route('/')
def homepage():
    return render_template('login.jhtml', form=LoginForm(request.form))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        return redirect('/')
    return render_template('register.jhtml', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        return redirect('/')
    return render_template('login.jhtml', form=form)

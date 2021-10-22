from flask import render_template, request, redirect
from forms import LoginForm, RegistrationForm
from app import app


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

# PasswordManager

Simple password manager, university project

## Running

Clone the repo, and make sure you have `pipenv` installed.
Then, use `pipenv` to create virtual environment for the app, and install all the dependencies:

```shell
pipenv sync
```

Afterwards, you can run the app with `flask`:

```shell
FLASK_APP=app.py pipenv run flask run
```

If you are working on not-bash-compatible shell, make sure to create env variable `FLASK_APP` with value `app.py` before starting the development server.
Also, VSCode tasks are included for convenience.

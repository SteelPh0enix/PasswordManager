# PasswordManager

Simple password manager, university project

Link to this repository: https://github.com/SteelPh0enix/PasswordManager

## Running

Clone the repo, and make sure you have `pipenv` installed.
Then, use `pipenv` to create virtual environment for the app, and install all the dependencies:

```shell
pipenv sync
```

Then, you may want to enter the virtualenv and run some pip shennanigas

```shell
pipenv run pip install -e .
```

Afterwards, generate the `.env` file, containing secret keys and some settings with provided python script: `pipenv run generate_env.py`, and then you can run the app:

```shell
FLASK_APP='passwordmanager' FLASK_ENV='development' pipenv run flask run
```

If you are working on not-bash-compatible shell, make sure to create env variable `FLASK_APP` with value `app.py` before starting the development server.
Also, VSCode tasks are included for convenience. **Remember to generate .env file before doing anything! It will NOT run without it!**
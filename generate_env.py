from secrets import token_bytes
from os.path import exists

def main():
    if not exists('.env'):
        with open('.env', 'wt') as env_file:
            env_file.writelines([
                "SECRET_KEY={0}\n".format(token_bytes(32)),
                "CSRF_SECRET_KEY={0}\n".format(token_bytes(32)),
                "SQLALCHEMY_DATABASE_URI='sqlite:///db.sqlite'\n",
                "SQLALCHEMY_TRACK_MODIFICATIONS=True\n"
            ])

if __name__ == '__main__':
    main()
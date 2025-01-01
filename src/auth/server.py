import jwt, datetime, os, psycopg2
from flask import Flask, request
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from contextlib import contextmanager
from dotenv import load_dotenv


load_dotenv()
conn = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USERNAME'),
        password=os.getenv('DB_PASSWORD'))


server = Flask(__name__)
# mysql = MySQL(server)

# config
server.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
server.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(server, session_options={"autoflush": False})

class User(db.Model):
    """User table"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True)
    password = db.Column(db.String(255))

    def __repr__(self):
        return f'User: {self.email}'


# migrate = Migrate(server, db)
with server.app_context():
    db.create_all()

"""
@contextmanager
def session_manager():
    try:
        yield db.session
    except Exception:
        db.session.rollback()
        raise
    finally:
        db.session.close()
"""


@server.route("/login", methods=["POST"])
def login():
    print('what is auth', flush=True)
    print(request.authorization, flush=True)

    auth = request.authorization
    if not auth:
        return "missing credentials", 401

    # check db for username and password
    # Open a cursor to perform database operations
    cur = conn.cursor()
    cur.execute(
        "SELECT email, password FROM public.user WHERE email=%s", (auth.username,)
    )
    userFound = cur.fetchone()

    if len(userFound) > 0:
        email = userFound[0]
        password = userFound[1]

        print('found email', flush=True)
        print(email, flush=True)
        print(password, flush=True)

        if auth.username != email or auth.password != password:
            return "invalid credentials, but found in DB", 401
        else:
            return createJWT(auth.username, os.getenv("JWT_SECRET"), True)
    else:
        return "invalid credentials, not found in DB", 401


@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "missing credentials", 401

    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            # encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
            encoded_jwt, os.getenv("JWT_SECRET"), algorithms=["HS256"]
        )
    except:
        return "not authorized", 403

    return decoded, 200


def createJWT(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)

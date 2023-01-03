import datetime
import os
import re

import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

server = Flask(__name__)
MYSQL_HOST = os.environ.get("MYSQL_HOST")
MYSQL_USER = os.environ.get("MYSQL_USER")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD")
MYSQL_DB = os.environ.get("MYSQL_DB")
MYSQL_PORT = os.environ.get("MYSQL_PORT")
server.config[
    "SQLALCHEMY_DATABASE_URI"
] = f"mysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"

CORS(server)

db = SQLAlchemy(server)
migrate = Migrate()
migrate.init_app(server, db)


class Validator:
    @staticmethod
    def validate(data, regex):
        """Custom Validator"""
        return True if re.match(regex, data) else False

    def validate_password(self, password: str):
        """Password Validator"""
        reg = r"\b^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$\b"
        return self.validate(password, reg)

    def validate_email(self, email: str):
        """Email Validator"""
        regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        return self.validate(email, regex)

    def validate_user(self, **args):
        """User Validator"""
        if (
            not args.get("email")
            or not args.get("password")
            or not args.get("first_name")
            or not args.get("last_name")
            or not args.get("username")
            or not args.get("roles")
        ):
            return {
                "email": "Email is required",
                "password": "Password is required",
                "first_name": "First name is required",
                "last_name": "Last name is required",
                "username": "Username is required",
                "roles": "Roles is required",
            }
        if not (
            isinstance(args.get("first_name"), str)
            or isinstance(args.get("last_name"), str)
            or isinstance(args.get("username"), str)
            or isinstance(args.get("email"), str)
            or isinstance(args.get("password"), str)
            or isinstance(args.get("roles"), str)
        ):
            return {
                "email": "Email must be a string",
                "password": "Password must be a string",
                "username": "Username must be a string",
                "first_name": "First name must be a string",
                "last_name": "Last name must be a string",
                "roles": "Roles must be a string",
            }
        if not self.validate_email(args.get("email")):
            return {"email": "Email is invalid"}
        if not self.validate_password(args.get("password")):
            return {
                "password": "Password is invalid, Should be atleast 8 characters with \
                    upper and lower case letters, numbers and special characters"
            }
        if not 3 <= len(args["username"]) <= 30:
            return {"name": "Username must be between 3 and 30 characters"}
        if args["roles"] not in ["student", "instructor"]:
            return {"roles": "Roles must be either student or instructor"}
        return True

    def validate_email_and_password(self, email, password):
        """Email and Password Validator"""
        if not (email and password):
            return {"email": "Email is required", "password": "Password is required"}
        if not self.validate_email(email):
            return {"email": "Email is invalid"}
        if not self.validate_password(password):
            return {
                "password": "Password is invalid, Should be atleast 8 characters with \
                    upper and lower case letters, numbers and special characters"
            }
        return True


class HttpException(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict({"error": self.payload or {}})
        rv["message"] = self.message
        return rv


@server.errorhandler(HttpException)
def handle_http_exception(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), unique=True, nullable=False)
    first_name = db.Column(db.String(200), nullable=False)
    last_name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200), unique=True, nullable=False)
    roles = db.Column(db.String(200), nullable=False)

    def as_dict(self):
        return {
            c.name: getattr(self, c.name)
            for c in self.__table__.columns
            if c.name != "password_hash"
        }


@server.route("/signup", methods=["POST"])
def signup():
    user = request.json
    if not user:
        raise HttpException(
            "Bad request", status_code=400, payload="Please provide user details"
        )
    is_validated = Validator().validate_user(**user)
    if is_validated is not True:
        raise HttpException("Invalid data", status_code=400, payload=is_validated)
    if User.query.filter_by(email=user["email"]).first():
        raise HttpException(
            "Conflict",
            status_code=409,
            payload="User already exists with this email address",
        )
    if User.query.filter_by(username=user["username"]).first():
        raise HttpException(
            "Conflict", status_code=409, payload="Username already taken"
        )

    new_user = User(
        email=user["email"],
        password_hash=generate_password_hash(user["password"]),
        first_name=user["first_name"],
        last_name=user["last_name"],
        username=user["username"],
        roles=user["roles"],
    )
    db.session.add(new_user)
    db.session.commit()
    return (
        jsonify(createJWT(new_user.as_dict(), os.environ.get("JWT_SECRET"), True)),
        201,
    )


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        raise HttpException(
            "Unauthorized", status_code=401, payload="Please provide user credentials"
        )
    email, password = auth["username"], auth["password"]
    validator = Validator()
    is_validated = validator.validate_email_and_password(email, password)
    if is_validated is not True:
        raise HttpException("Bad request", status_code=400, payload=is_validated)
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        raise HttpException(
            "Unauthorized", status_code=401, payload="Invalid email or password"
        )
    return jsonify(createJWT(user.as_dict(), os.environ.get("JWT_SECRET"), True)), 200


@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]
    if not encoded_jwt:
        raise HttpException(
            "Unauthorized", status_code=401, payload="Please provide bearer token"
        )
    encoded_jwt = encoded_jwt.split(" ")[1]
    try:
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
        )
    except Exception as e:
        raise HttpException("Unauthorized", status_code=401, payload=e)
    return decoded, 200


def createJWT(user, secret, authz):
    return jwt.encode(
        {
            "user": user,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)

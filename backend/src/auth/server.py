import datetime
import os
import re

import jwt
from flask import Flask, request
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
        if not args.get("email") or not args.get("password") or not args.get("name"):
            return {
                "email": "Email is required",
                "password": "Password is required",
                "name": "Name is required",
            }
        if (
            not isinstance(args.get("name"), str)
            or not isinstance(args.get("email"), str)
            or not isinstance(args.get("password"), str)
        ):
            return {
                "email": "Email must be a string",
                "password": "Password must be a string",
                "name": "Name must be a string",
            }
        if not self.validate_email(args.get("email")):
            return {"email": "Email is invalid"}
        if not self.validate_password(args.get("password")):
            return {
                "password": "Password is invalid, Should be atleast 8 characters with \
                    upper and lower case letters, numbers and special characters"
            }
        if not 2 <= len(args["name"].split(" ")) <= 30:
            return {"name": "Name must be between 2 and 30 words"}
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


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), unique=True, nullable=False)


@server.route("/signup", methods=["POST"])
def signup():
    user = request.json
    if not user:
        return {
            "message": "Please provide user details",
            "data": None,
            "error": "Bad request",
        }, 400
    is_validated = Validator().validate_user(**user)
    if is_validated is not True:
        return dict(message="Invalid data", data=None, error=is_validated), 400
    user.pop("name")
    if User.query.filter_by(email=user["email"]).first():
        return {
            "message": "User already exists",
            "error": "Conflict",
            "data": None,
        }, 409

    new_user = User(
        email=user["email"], password_hash=generate_password_hash(user["password"])
    )
    db.session.add(new_user)
    db.session.commit()
    return createJWT(user["email"], os.environ.get("JWT_SECRET"), True), 201


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return {
            "message": "Please provide user credentials",
            "data": None,
            "error": "Bad request",
        }, 400
    email, password = auth["username"], auth["password"]
    validator = Validator()
    is_validated = validator.validate_email_and_password(email, password)
    if is_validated is not True:
        return dict(message="Invalid data", data=None, error=is_validated), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return {
            "message": "Invalid email or password",
            "data": None,
            "error": "Invalid Credentials",
        }, 401
    return createJWT(email, os.environ.get("JWT_SECRET"), True), 200


@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]
    if not encoded_jwt:
        return {
            "message": "Please provide bearer token",
            "data": None,
            "error": "Bad request",
        }, 400
    encoded_jwt = encoded_jwt.split(" ")[1]
    try:
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
        )
    except Exception as e:
        return {"message": e, "data": None, "error": "Unauthorized"}, 403
    return decoded, 200


def createJWT(email, secret, authz):
    return jwt.encode(
        {
            "email": email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)

import base64
import os

import jwt
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication


def get_authorization_header(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    return auth


class BasicAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != "basic":
            return None

        if len(auth) == 1:
            raise exceptions.AuthenticationFailed(
                "Invalid basic header. No credentials provided."
            )
        if len(auth) > 2:
            raise exceptions.AuthenticationFailed(
                "Invalid basic header. Credential string is not properly formatted"
            )
        try:
            auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
            username, password = auth_decoded.split(":")
        except (UnicodeDecodeError, ValueError):
            raise exceptions.AuthenticationFailed(
                "Invalid basic header. Credentials not correctly encoded"
            )

        return {"username": username, "password": password}, None


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != "bearer":
            return None

        if len(auth) == 1:
            msg = "Invalid token header. No credentials provided."
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = "Invalid token header. Token string should not contain spaces."
            raise exceptions.AuthenticationFailed(msg)
        encoded_token = auth[1]
        try:
            decoded = jwt.decode(
                encoded_token, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
            )
        except UnicodeError:
            msg = "Invalid token header. Token string should not contain invalid characters."
            raise exceptions.AuthenticationFailed(msg)

        return decoded["user"], None

import os

import requests
from gateway.helpers.exceptions import CustomException
from rest_framework import status
from rest_framework.exceptions import NotAuthenticated

AUTH_SVC_HOST = f"http://{os.environ.get('AUTH_SVC_ADDRESS')}"


def login(request):
    user = request.user
    if not user:
        raise NotAuthenticated("Missing credentials")
    response = requests.post(
        f"{AUTH_SVC_HOST}/login", auth=(user["username"], user["password"])
    )

    if response.status_code == 200:
        return response.json(), None
    else:
        return None, (response.json()["error"], response.status_code)


def signup(request):
    body = request.data
    if not body:
        raise CustomException(
            "Please provide a valid body", code=status.HTTP_400_BAD_REQUEST
        )
    response = requests.post(f"{AUTH_SVC_HOST}/signup", json=body)

    if response.status_code == 201:
        return response.json(), None
    else:
        return None, (response.json()["error"], response.status_code)

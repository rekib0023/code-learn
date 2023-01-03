import base64
import os

import requests
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
        return response.text, None
    else:
        return None, (response.json()["error"], response.status_code)

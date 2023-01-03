from rest_framework.decorators import api_view, authentication_classes
from rest_framework.response import Response

from gateway.helpers.authentication import BasicAuthentication, JWTAuthentication
from gateway.helpers.exceptions import CustomException

from .services import access


@api_view(["POST"])
@authentication_classes([BasicAuthentication])
def login(request):
    token, err = access.login(request)
    if not err:
        return Response(token, content_type="text/plain")
    else:
        raise CustomException(detail=err[0], code=err[1])


@api_view(["POST"])
# @authentication_classes([JWTAuthentication])
def signup(request):
    print(request)
    pass


@api_view(["POST"])
def logout(request):
    pass

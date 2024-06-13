from rest_framework import response, decorators as rest_decorators, permissions as rest_permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiTypes
from user.serializers import ErrorResponseSerializer


@extend_schema(
    description="Endpoint to pay for subscription.",
    responses={
        200: {
            "type": "object",
                "properties": {
                    "msg": {
                        "type": "string",
                    }
                }
            },
        401: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Unauthorized")
    }
)
@rest_decorators.api_view(["POST"])
@rest_decorators.authentication_classes([JWTAuthentication])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    """Endpoint to pay for subscription."""
    return response.Response({"msg": "Success"}, 200)


@extend_schema(
    description="Endpoint to pay for subscription.",
    responses={
        200: {
            "type": "object",
                "properties": {
                    "msg": {
                        "type": "string",
                    }
                }
            },
        401: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Unauthorized")
    }
)
@rest_decorators.api_view(["POST"])
@rest_decorators.authentication_classes([JWTAuthentication])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    """Endpoint to list subscriptions."""
    return response.Response({"msg": "Success"}, 200)

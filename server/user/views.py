import stripe
from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from rest_framework import (
    exceptions as rest_exceptions,
    response,
    decorators as rest_decorators,
    permissions as rest_permissions
)
from rest_framework_simplejwt import (
    tokens,
    views as jwt_views,
    serializers as jwt_serializers,
    exceptions as jwt_exceptions
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_spectacular.utils import (
    extend_schema, OpenApiTypes, OpenApiResponse, inline_serializer
)
from rest_framework import serializers as serializer

from user import serializers, models
from user.serializers import ErrorResponseSerializer

stripe.api_key = settings.STRIPE_SECRET_KEY
prices = {
    settings.WORLD_INDIVIDUAL: "world_individual",
    settings.WORLD_GROUP: "world_group",
    settings.WORLD_BUSINESS: "world_business",
    settings.UNIVERSE_INDIVIDUAL: "universe_individual",
    settings.UNIVERSE_GROUP: "universe_group",
    settings.UNIVERSE_BUSINESS: "universe_business"
}


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token)
    }


@extend_schema(
    request=serializers.LoginSerializer,
    responses={
        200: OpenApiResponse(response=inline_serializer(
            name="TokenResponseSerializer",
            fields={"access_token": serializer.CharField(),
                    "refresh_token": serializer.CharField()}
        )),
        401: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Unauthorized")
    },
    methods=["POST"],
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def loginView(request):
    """
        Authenticate a user and initiate a session by setting JWT tokens as cookies.

        This endpoint allows a user to log in by providing their email and password.
        Upon successful authentication, access and refresh JWT tokens are returned and set as cookies.
        The tokens are also included in the response body.
    """

    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        res.data = tokens
        res["X-CSRFToken"] = csrf.get_token(request)
        return res
    raise rest_exceptions.AuthenticationFailed(
        "Email or Password is incorrect!"
    )


@extend_schema(
    request=serializers.RegistrationSerializer,
    responses={
        200: OpenApiResponse(response=OpenApiTypes.STR),
        400: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Bad Request")
    },
    methods=["POST"],
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def registerView(request):
    """This endpoint allows users to register a new account.
    The user needs to provide a first_name, last_name, email, password, password2. 
    On successful registration user will get the message the account was created. """

    serializer = serializers.RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response("Registered!")
    return rest_exceptions.AuthenticationFailed("Invalid credentials!")


@extend_schema(
    responses={
        200: None,
        401: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Unauthorized")
    },
    methods=["POST"],
)
@rest_decorators.api_view(['POST'])
@rest_decorators.authentication_classes([JWTAuthentication])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    """This endpoint allows an authenticated user to log out by blacklisting the refresh token
       and clearing the authentication cookies. If the refresh token is invalid or not found,
       a 401 error is returned."""
    try:
        refreshToken = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        token = tokens.RefreshToken(refreshToken)
        token.blacklist()

        res = response.Response()
        res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        res.delete_cookie("X-CSRFToken")
        res.delete_cookie("csrftoken")
        res["X-CSRFToken"]=None
        
        return res
    except:
        raise rest_exceptions.ParseError("Invalid token")


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                'No valid token found in cookie \'refresh\'')


@extend_schema(
    request=None,
    responses={
        200: inline_serializer(name="RefreshToken", fields={
            "access_token": serializer.CharField()
        }),
        401: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Unauthorized")
    }
)
class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    """This endpoint allows users to refresh their JWT tokens using the refresh token
    stored in cookies. If the refresh token is valid, a new access token is returned.
    If the refresh token is invalid or expired, a 401 Unauthorized error is returned."""

    serializer_class = CookieTokenRefreshSerializer
    authentication_classes = (JWTAuthentication,)

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=response.data['refresh'],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


@extend_schema(
    responses={
        200: inline_serializer(name="UserSerializer", fields={
            "id": serializer.IntegerField(),
            "email": serializer.EmailField(),
            "is_staff": serializer.BooleanField(),
            "first_name": serializer.CharField(),
            "last_name": serializer.CharField()
        }),
        401: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Unauthorized")
    },
    methods=["GET"]
    )
@rest_decorators.api_view(["GET"])
@rest_decorators.authentication_classes([JWTAuthentication])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    """Retrieve information about the authenticated user."""

    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    serializer = serializers.UserSerializer(user)
    return response.Response(serializer.data)


@extend_schema(
        responses={
            200: {
                "type": "object",
                "properties": {
                    "subscriptions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "start_date": {"type": "string"},
                                "plan": {"type": "string"}
                            },
                            "required": ["id", "start_date", "plan"]
                        }
                    }
                }
            },
            401: OpenApiResponse(response=ErrorResponseSerializer, description="Error: Unauthorized")
        },
        methods=["GET"],
    )
@rest_decorators.api_view(["GET"])
@rest_decorators.authentication_classes([JWTAuthentication])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def getSubscriptions(request):
    """Retrieve the subscriptions of the authenticated user."""
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    subscriptions = []
    customer = stripe.Customer.search(query=f'email:"{user.email}"')
    if "data" in customer:
        if len(customer["data"]) > 0:
            for _customer in customer["data"]:
                subscription = stripe.Subscription.list(customer=_customer["id"])
                if "data" in subscription:
                    if len(subscription["data"]) > 0:
                        for _subscription in subscription["data"]:
                            if _subscription["status"] == "active":
                                subscriptions.append({
                                    "id": _subscription["id"],
                                    "start_date": str(_subscription["start_date"]),
                                    "plan": prices[_subscription["plan"]["id"]]
                                })

    return response.Response({"subscriptions": subscriptions}, 200)

from datetime import timedelta

import pyotp
from django.contrib.auth import authenticate
from django.db import transaction, IntegrityError
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainSerializer, TokenBlacklistSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenBlacklistView, TokenRefreshView

from apps.common.responses import CustomResponse
from apps.core.emails import send_otp_email
from apps.core.models import TenantProfile, LandLordProfile
from apps.core.serializers import *

User = get_user_model()


# Create your views here.


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer

    @extend_schema(
        summary="Registration",
        description=
        """
        This endpoint allows a new user to register an account.
        The request should include the following data:
        
        - `first_name`: The user's first name.
        - `last_name`: The user's last name.
        - `email`: The user's email address.
        - `phone_number`: The user's phone number.
        - `password`: The user's password.
    
        If the registration is successful, the response will include the following data:
    
        - `message`: A success message indicating that the user has been registered.
        - `status`: The status of the request.
        """,
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                description="Registered successfully. Check email for verification code, verification code for phone will be sent after email has been verified",
                response=RegisterSerializer
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="Email already exists"
            )
        }
    )
    @transaction.atomic()
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = User.objects.create_user(**serializer.validated_data)
        except IntegrityError:
            return CustomResponse.generate_response(code=409, msg={"code": 3, "message": "Email already exists"})

        send_otp_email(user)
        response_data = {
            "code": 0,
            "message": "Registered successfully. Check email for verification code",
        }
        return CustomResponse.generate_response(code=201, msg=response_data)


class VerifyEmailView(GenericAPIView):
    serializer_class = VerifyEmailSerializer

    @extend_schema(
        summary="Email verification",
        description=
        """
        This endpoint allows a registered user to verify their email address with an OTP.
        The request should include the following data:

        - `email_address`: The user's email address.
        - `otp`: The otp sent to the user's email address.

        If the verification  is successful, the response will include the following data:

        - `message`: A success message indicating that the user has been registered.
        - `status`: The status of the request.
        """,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Email verification successful.",
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="Email verified already"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="OTP Error"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="User with this email not found"
            )
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        code = self.request.data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            response_data = {"code": 1, "message": "User with this email not found"}
            return CustomResponse.generate_response(code=404, msg=response_data)

        if user.email_verified:
            response_data = {"code": 3, "message": "Email already verified"}
            return CustomResponse.generate_response(code=409, msg=response_data)
        elif not code or not user.otp_secret:
            response_data = {"code": 1, "message": "No OTP found for this account"}
            return CustomResponse.generate_response(code=404, msg=response_data)

        # Check if the OTP secret has expired (10 minutes interval)
        current_time = timezone.now()
        expiration_time = user.otp_secret.created + timedelta(minutes=10)
        if current_time > expiration_time:
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "OTP has expired"})

        # Verify the OTP
        totp = pyotp.TOTP(user.otp_secret.secret, interval=600)
        if not totp.verify(code):
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "Invalid OTP"})

        # OTP verification successful, proceed with further logic
        user.email_verified = True
        user.save()
        user.otp_secret.delete()
        response_data = {
            "code": 0,
            "message": "Email verification successful.",
        }
        return CustomResponse.generate_response(code=200, msg=response_data)


class ResendEmailVerificationCodeView(GenericAPIView):
    serializer_class = ResendEmailVerificationCodeSerializer

    @extend_schema(
        summary="Resend email verification code",
        description=
        """
        This endpoint allows a registered user to resend email verification code to their registered email address.
        The request should include the following data:

        - `email_address`: The user's email address.

        If the request is successful, the response will include the following data:

        - `message`: A success message indicating that the user has been registered.
        - `status`: The status of the request.
        """,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Verification code sent successfully. Please check your mail.",
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="Email verified already, no need to resend"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="User with this email not found"
            )
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            response_data = {"code": 1, "message": "User with this email not found"}
            return CustomResponse.generate_response(code=404, msg=response_data)

        if user.email_verified:
            response_data = {"code": 3, "message": "Email already verified, no need to resend"}
            return CustomResponse.generate_response(code=409, msg=response_data)

        send_otp_email(user)
        response_data = {
            "code": 0,
            "message": "Verification code sent successfully. Please check your mail"
        }
        return CustomResponse.generate_response(code=200, msg=response_data)


class SendNewEmailVerificationCodeView(GenericAPIView):
    serializer_class = SendNewEmailVerificationCodeSerializer

    @extend_schema(
        summary="Resend email change verification code",
        description=
        """
        This endpoint allows an authenticated user to send a verification code to new email they want to change to.
        The request should include the following data:

        - `email_address`: The user's new email address.

        If the request is successful, the response will include the following data:

        - `message`: A success message indicating that the user has been registered.
        - `status`: The status of the request.
        """,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Verification code sent successfully. Please check your new email.",
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="Account with this email already exists"
            )
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')

        if User.objects.filter(email=email).exists():
            response_data = {"code": 3, "message": "Account with this email already exists"}
            return CustomResponse.generate_response(code=409, msg=response_data)
        else:
            send_otp_email(self.request.user, email)
            response_data = {"code": 0, "message": "Verification code sent successfully. Please check your new email."}
            return CustomResponse.generate_response(code=200, msg=response_data)


class ChangeEmailView(GenericAPIView):
    serializer_class = ChangeEmailSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Change account email address",
        description=
        """
        This endpoint allows an authenticated user to change their account's email address and user can change after 10 days.
        The request should include the following data:

        - `email_address`: The user's new email address.
        - `otp`: The code sent

        If the request is successful, the response will include the following data:

        - `message`: A success message indicating that the user has been registered.
        - `status`: The status of the request.
        """,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Email changed successfully.",
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="You can't use your previous email"
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="OTP Error"
            ),
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        new_email = serializer.validated_data.get('email')
        code = self.request.data.get('code')
        user = self.request.user

        if user.email == new_email:
            response_data = {"code": 3, "message": "You can't use your previous email"}
            return CustomResponse.generate_response(code=409, msg=response_data)
        elif not code or not user.otp_secret:
            response_data = {"code": 1, "message": "No OTP found for this account"}
            return CustomResponse.generate_response(code=404, msg=response_data)

        # Check if the OTP secret has expired (10 minutes interval)
        current_time = timezone.now()
        expiration_time = user.otp_secret.created + timedelta(minutes=10)
        if current_time > expiration_time:
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "OTP has expired"})

        # Verify the OTP
        totp = pyotp.TOTP(user.otp_secret.secret, interval=600)
        if not totp.verify(code):
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "Invalid OTP"})

        user.email = new_email
        user.email_changed = True
        user.save()
        user.otp_secret.delete()
        response_data = {
            "code": 0,
            "message": "Email changed successfully.",
        }
        return CustomResponse.generate_response(code=200, msg=response_data)


class LoginView(TokenObtainPairView):
    serializer_class = TokenObtainSerializer
    throttle_classes = [UserRateThrottle]

    @staticmethod
    def get_profile_serializer(user):
        if isinstance(user, TenantProfile):
            return TenantProfileSerializer(user)
        elif isinstance(user, LandLordProfile):
            return LandLordProfileSerializer(user)
        else:
            return None

    @extend_schema(
        summary="Login",
        description=
        """
        This endpoint authenticates a registered and verified user and provides the necessary authentication tokens.
        The request should include the following data:

        - `email`: The user's email address.
        - `password`: The user's password.

        If the login is successful, the response will include the following data:

        - `access`: The access token used for authorization.
        - `refresh`: The refresh token used for obtaining a new access token.
        - `data`: The profile data of the user
        """

    )
    def post(self, request):
        serializer = LoginSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        user = authenticate(request, email=email, password=password)
        if not user:
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "Invalid credentials"})
        if not user.email_verified:
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "Verify your email first"})

        profile_serializer = self.get_profile_serializer(user=user)
        tokens = super().post(request).data

        response_data = {"tokens": tokens, "profile_data": profile_serializer.data if profile_serializer else ""}
        response_message = {
            "code": 0, "message": "Logged in successfully",
        }
        return CustomResponse.generate_response(code=200, data=response_data, msg=response_message)


class LogoutView(TokenBlacklistView):
    serializer_class = TokenBlacklistSerializer

    @extend_schema(
        summary="Logout",
        description=
        """
        This endpoint logs out an authenticated user by blacklisting their access token.
        The request should include the following data:

        - `refresh`: The refresh token used for authentication.

        If the logout is successful, the response will include the following data:

        - `message`: A success message indicating that the user has been logged out.
        - `status`: The status of the request.
        """
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            return CustomResponse.generate_response(code=200, msg={"code": 0, "message": "Logged out successfully."})
        except TokenError:
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "Token is blacklisted."})


class RefreshView(TokenRefreshView):
    serializer_class = TokenRefreshSerializer

    @extend_schema(
        summary="Refresh token",
        description=
        """
        This endpoint allows a user to refresh an expired access token.
        The request should include the following data:

        - `access`: The expired access token.

        If the token refresh is successful, the response will include the following data:

        - `message`: A success message indicating that the token has been refreshed.
        - `token`: The new access token.
        - `status`: The status of the request.
        """

    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        access_token = serializer.validated_data['access']
        response_data = {
            "code": 0,
            "message": "Refreshed successfully",
        }
        return CustomResponse.generate_response(code=200, data={"token": access_token}, msg=response_data)

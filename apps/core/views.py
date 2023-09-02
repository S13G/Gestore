from datetime import timedelta

import pyotp
from django.contrib.auth import authenticate
from django.db import transaction, IntegrityError
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenBlacklistSerializer, \
    TokenRefreshSerializer, TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenBlacklistView, TokenRefreshView

from apps.common.permissions import IsAuthenticatedTenant, IsAuthenticatedLandLord
from apps.common.responses import CustomResponse
from apps.core.emails import send_otp_email
from apps.core.models import TenantProfile, LandLordProfile
from apps.core.serializers import *
from utilities.encryption import decrypt_token_to_profile, encrypt_profile_to_token

User = get_user_model()

# Create your views here.

"""
AUTHENTICATION AND OTHER AUTH OPTIONS
"""


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
        """,
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                description="Registered successfully.",
                response=RegisterSerializer
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="Email already exist"
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

        response_data = {
            "code": 0,
            "message": "Registered successfully.",
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
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangeEmailSerializer

    @extend_schema(
        summary="Change account email address",
        description=
        """
        This endpoint allows an authenticated user to change their account's email address and user can change after 10 days.
        The request should include the following data:

        - `email_address`: The user's new email address.
        - `otp`: The code sent
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
    serializer_class = TokenObtainPairSerializer
    throttle_classes = [AnonRateThrottle]

    @staticmethod
    def get_profile_serializer(user):
        if hasattr(user, "tenant_profile"):
            return TenantProfileSerializer(user.tenant_profile)
        elif hasattr(user, "landlord_profile"):
            return LandLordProfileSerializer(user.landlord_profile)
        else:
            return None

    @extend_schema(
        summary="Login",
        description="This endpoint authenticates a registered and verified user and provides the necessary authentication tokens.",
        request=LoginSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Logged in successfully",
                response=LoginSerializer,
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Account not active or Invalid credentials",
            ),
        }
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

        tokens_response = super().post(request)

        profile_serializer = self.get_profile_serializer(user=user)

        response_data = {"tokens": tokens_response.data,
                         "profile_data": profile_serializer.data if profile_serializer else ""}
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
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Token is blacklisted",
            ),
            status.HTTP_200_OK: OpenApiResponse(
                description="Logged out successfully"
            )
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
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

        - `refresh`: The refresh token.
        """,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Refreshed successfully",
            ),
        }

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


class RequestForgotPasswordCodeView(GenericAPIView):
    serializer_class = RequestNewPasswordCodeSerializer
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        summary="Request new password code for forgot password",
        description=
        """
        This endpoint allows a user to request a verification code to reset their password if forgotten.
        The request should include the following data:

        - `email`: The user's email address.
        """,
        responses={
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Account not found"
            ),
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Password code sent successfully"
            )
        }

    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = self.request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return CustomResponse.generate_response(code=404, msg={"code": 1, "message": "Account not found"})
        send_otp_email(user, email)
        return CustomResponse.generate_response(code=200, msg={"code": 0, "message": "Password code sent successfully"})


class VerifyForgotPasswordCodeView(GenericAPIView):
    serializer_class = VerifyEmailSerializer
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        summary="Verify forgot password code for unauthenticated users",
        description=
        """
        This endpoint allows a user to verify the verification code they got to reset the password if forgotten.
        The user will be stored in the token which will be gotten to make sure it is the right user that is
        changing his/her password

        The request should include the following data:

        - `email`: The user's email
        - `otp`: The verification code sent to the user's email.
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="OTP error"
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Account not found"
            ),
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Otp verified successfully"
            )
        }

    )
    @transaction.atomic()
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        email = self.request.data.get("email")
        code = self.request.data.get("otp")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return CustomResponse.generate_response(code=404, msg={"code": 1, "message": "Account not found"})

        if not code or not user.otp_secret:
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

        token = encrypt_profile_to_token(user)  # Encrypt the user profile to a token.
        response_data = {"code": 0, "message": "Otp verified successfully"}
        return CustomResponse.generate_response(code=200, data={"token": token}, msg=response_data)


class ChangeForgottenPasswordView(GenericAPIView):
    serializer_class = ChangePasswordSerializer
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        summary="Change password for forgotten password",
        description=
        """
        This endpoint allows the unauthenticated user to change their password after requesting for a code.
        The request should include the following data:

        - `password`: The new password.
        - `confirm_password`: The new password again.
        """,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Password updated successfully",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Token not provided"
            )
        }
    )
    @transaction.atomic()
    def post(self, request, *args, **kwargs):
        token = self.kwargs.get('token')
        if token is None:
            return CustomResponse.generate_response(code=400, msg={"code": 2, "message": "Token not provided"})
        user = decrypt_token_to_profile(token)
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']
        user.set_password(password)
        user.save()

        return CustomResponse.generate_response(code=200, msg={"code": 0, "message": "Password updated successful"})


class ChangePasswordView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        summary="Change password for authenticated users",
        description=
        """
        This endpoint allows the authenticated user to change their password.
        The request should include the following data:

        - `password`: The new password.
        - `confirm_password`: The new password again.
        """,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Password updated successfully",
            ),
        }
    )
    @transaction.atomic()
    def post(self, request):
        user = self.request.user
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']
        user.set_password(password)
        user.save()
        return CustomResponse.generate_response(code=200, msg={"code": 0, "message": "Password updated successful"})


"""
PROFILE CREATION
"""


class CreateTenantProfileView(GenericAPIView):
    serializer_class = TenantProfileSerializer
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        summary="Create tenant profile",
        description=
        """
        This endpoint allows a user to create a tenant profile.
        """,
        responses={
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="You already have an existing tenant profile",
            ),
        }
    )
    @transaction.atomic()
    def post(self, request):
        user = self.request.user
        if hasattr(user, "tenant_profile"):
            response_data = {"profile": self.serializer_class(user.tenant_profile).data}
            response_msg = {"code": 3, "message": "You already have an existing tenant profile"}
            return CustomResponse.generate_response(code=409, data=response_data, msg=response_msg)
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        created_profile = TenantProfile.objects.create(user=user, **serializer.validated_data)
        profile = self.serializer_class(created_profile).data
        return CustomResponse.generate_response(code=201, data={"profile": profile})


class CreateLandlordProfileView(GenericAPIView):
    serializer_class = LandLordProfileSerializer
    permission_classes = (IsAuthenticated,)

    @extend_schema(
        summary="Create landlord profile",
        description=
        """
        This endpoint allows a user to create a landlord profile.
        """,
        responses={
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description="You already have an existing landlord profile",
            ),
        }
    )
    @transaction.atomic()
    def post(self, request):
        user = self.request.user
        if hasattr(user, "landlord_profile"):
            response_data = {"profile": self.serializer_class(user.landlord_profile).data}
            response_msg = {"code": 3, "message": "You already have an existing landlord profile"}
            return CustomResponse.generate_response(code=409, data=response_data, msg=response_msg)
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        created_profile = LandLordProfile.objects.create(user=user, **serializer.validated_data)
        profile = self.serializer_class(created_profile).data
        return CustomResponse.generate_response(code=201, data={"profile": profile})


class RetrieveUpdateDeleteTenantProfileView(GenericAPIView):
    permission_classes = (IsAuthenticatedTenant,)
    serializer_class = TenantProfileSerializer

    @extend_schema(
        summary="Retrieve tenant profile",
        description=
        """
        This endpoint allows a user to retrieve his/her tenant profile.
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide profile id"
            ),
            status.HTTP_200_OK: OpenApiResponse(
                description="Fetched successfully"
            )
        }
    )
    def get(self, request, *args, **kwargs):
        profile_id = self.kwargs.get('profile_id')
        if profile_id is None:
            return CustomResponse.generate_response(code=400)
        tenant_profile = TenantProfile.objects.get(id=profile_id)
        serialized_data = TenantProfileSerializer(tenant_profile).data
        return CustomResponse.generate_response(code=200, data=serialized_data)

    @extend_schema(
        summary="Update tenant profile",
        description=
        """
        This endpoint allows a user to update his/her tenant profile.
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide profile id"
            ),
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Updated successfully"
            )
        }
    )
    def patch(self, request, *args, **kwargs):
        profile_id = self.kwargs.get('profile_id')
        if profile_id is None:
            return CustomResponse.generate_response(code=400)
        tenant_profile = TenantProfile.objects.get(id=profile_id)
        update_profile = self.serializer_class(tenant_profile, data=self.request.data, partial=True,
                                               context={"request": request})
        update_profile.is_valid(raise_exception=True)
        updated = self.serializer_class(update_profile.save()).data
        return CustomResponse.generate_response(code=202, data=updated)

    @extend_schema(
        summary="Delete tenant profile",
        description=
        """
        This endpoint allows a user to delete his/her tenant profile.
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide profile id"
            ),
            status.HTTP_204_NO_CONTENT: OpenApiResponse(
                description="Fetched successfully"
            )
        }
    )
    def delete(self, request, *args, **kwargs):
        profile_id = self.kwargs.get('profile_id')
        if profile_id is None:
            return CustomResponse.generate_response(code=400)
        TenantProfile.objects.get(id=profile_id).delete()
        return CustomResponse.generate_response(code=204)


class RetrieveUpdateDeleteLandLordProfileView(GenericAPIView):
    permission_classes = (IsAuthenticatedLandLord,)
    serializer_class = LandLordProfileSerializer

    @extend_schema(
        summary="Retrieve landlord profile",
        description=
        """
        This endpoint allows a user to retrieve his/her landlord profile.
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide profile id"
            ),
            status.HTTP_200_OK: OpenApiResponse(
                description="Fetched successfully"
            )
        }
    )
    def get(self, request, *args, **kwargs):
        profile_id = self.kwargs.get('profile_id')
        if profile_id is None:
            return CustomResponse.generate_response(code=400)
        landlord_profile = LandLordProfile.objects.get(id=profile_id)
        serialized_data = LandLordProfileSerializer(landlord_profile).data
        return CustomResponse.generate_response(code=200, data=serialized_data)

    @extend_schema(
        summary="Update landlord profile",
        description=
        """
        This endpoint allows a user to update his/her landlord profile.
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide profile id"
            ),
            status.HTTP_202_ACCEPTED: OpenApiResponse(
                description="Updated successfully"
            )
        }
    )
    def patch(self, request, *args, **kwargs):
        profile_id = self.kwargs.get('profile_id')
        if profile_id is None:
            return CustomResponse.generate_response(code=400)
        landlord_profile = LandLordProfile.objects.get(id=profile_id)
        update_profile = self.serializer_class(landlord_profile, data=self.request.data, partial=True,
                                               context={"request": request})
        update_profile.is_valid(raise_exception=True)
        updated = self.serializer_class(update_profile.save()).data
        return CustomResponse.generate_response(code=202, data=updated)

    @extend_schema(
        summary="Delete landlord profile",
        description=
        """
        This endpoint allows a user to delete his/her landlord profile.
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Provide profile id"
            ),
            status.HTTP_204_NO_CONTENT: OpenApiResponse(
                description="Deleted successfully"
            )
        }
    )
    def delete(self, request, *args, **kwargs):
        profile_id = self.kwargs.get('profile_id')
        if profile_id is None:
            return CustomResponse.generate_response(code=400)
        LandLordProfile.objects.get(id=profile_id).delete()
        return CustomResponse.generate_response(code=204)

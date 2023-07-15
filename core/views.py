from datetime import timedelta

import pyotp
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import GenericAPIView

from common.responses import CustomResponse
from core.emails import send_otp_email
from core.serializers import RegisterSerializer, VerifyEmailSerializer

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
            - `account_type`: The type of account the user wants to create.
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
            }
    )
    def post(self, request):
        with transaction.atomic():
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            data = serializer.data
            send_otp_email(request)
            response = CustomResponse(code=201, data=data,
                                      detail="Registered successfully. Check email for verification code, verification code for phone will be sent after email has been verified").get_full_details()
            return response.to_response()


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
                status.HTTP_201_CREATED: OpenApiResponse(
                        description="Verified successfully.",
                ),
            }
    )
    def post(self, request):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = self.request.data.get('email_address')
        code = self.request.data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return CustomResponse(code=404, detail="User with this email not found").get_full_details()

        if code is None:
            return CustomResponse(code=404, detail="No OTP found for this account").get_full_details()
        if not user.otsecret:
            return CustomResponse(code=404, detail="No OTP found for this account").get_full_details()

            # Check if the OTP secret has expired (10 minutes interval)
        current_time = timezone.now()
        expiration_time = user.otsecret.created + timedelta(minutes=10)
        if current_time > expiration_time:
            return CustomResponse(code=400, detail="OTP has expired").get_full_details()

        # Verify the OTP
        totp = pyotp.TOTP(user.otsecret.secret, interval=600)
        if not totp.verify(code):
            return CustomResponse(code=400, detail="Invalid OTP").get_full_details()

        # OTP verification successful, proceed with further logic
        user.otsecret.delete()
        return CustomResponse(code=200, detail="OTP verification successful").get_full_details()

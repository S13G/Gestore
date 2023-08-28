from django.contrib.auth import get_user_model
from rest_framework import serializers as sr

from apps.common.exceptions import CustomValidation, CustomEmailSerializer

User = get_user_model()


class RegisterSerializer(CustomEmailSerializer):
    first_name = sr.CharField()
    last_name = sr.CharField()
    email = sr.CharField()
    phone_number = sr.CharField(write_only=True)
    password = sr.CharField()

    @staticmethod
    def validate_phone_number(value):
        if not value.startswith('+'):
            raise CustomValidation(
                {
                    "code": 2,
                    "message": "Phone number must start with country code e.g. (+44).",
                    "status": "failed"
                }
            )
        elif not value[1:].isdigit():
            raise CustomValidation(
                {
                    "code": 2,
                    "message": "Phone number must be digits.",
                    "status": "failed"}
            )
        return value


class VerifyEmailSerializer(CustomEmailSerializer):
    email = sr.CharField()
    otp = sr.IntegerField()


class ResendEmailVerificationCodeSerializer(CustomEmailSerializer):
    email = sr.CharField()


class SendNewEmailVerificationCodeSerializer(CustomEmailSerializer):
    email = sr.CharField()


class ChangeEmailSerializer(CustomEmailSerializer):
    email = sr.CharField()
    otp = sr.IntegerField()


class TenantProfileSerializer(sr.Serializer):
    full_name = sr.CharField(source="user.get_full_name", read_only=True)
    avatar = sr.ImageField()
    email = sr.EmailField(source="user.email", read_only=True)
    email_verified = sr.BooleanField(source="user.email_verified", read_only=True)
    date_of_birth = sr.DateField()
    phone_number = sr.CharField(source="user.phone_number", read_only=True)
    emergency_phone_number = sr.CharField()
    occupation = sr.CharField()
    address = sr.CharField()


class LandLordProfileSerializer(sr.Serializer):
    full_name = sr.CharField(source="user.get_full_name", read_only=True)
    avatar = sr.ImageField()
    email = sr.EmailField(source="user.email", read_only=True)
    email_verified = sr.BooleanField(source="user.email_verified", read_only=True)
    phone_number = sr.CharField(source="user.phone_number", read_only=True)
    date_of_birth = sr.DateField()
    occupation = sr.CharField()


class LoginSerializer(CustomEmailSerializer):
    email = sr.CharField()
    password = sr.CharField(write_only=True)


class ChangePasswordSerializer(sr.Serializer):
    password = sr.CharField(max_length=50, min_length=6, write_only=True)
    confirm_pass = sr.CharField(max_length=50, min_length=6, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        confirm = attrs.get('confirm_pass')

        if confirm != password:
            raise CustomValidation(
                {
                    "code": 2,
                    "message": "Passwords do not match",
                    "status": "failed"
                }
            )

        return attrs


class RequestNewPasswordCodeSerializer(CustomEmailSerializer):
    email = sr.CharField()

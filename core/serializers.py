from django.contrib.auth import get_user_model
from rest_framework import serializers as sr

from common.exceptions import CustomValidation, CustomEmailSerializer
from core.choices import ACCOUNT_TYPE

User = get_user_model()


class RegisterSerializer(CustomEmailSerializer):
    first_name = sr.CharField()
    last_name = sr.CharField()
    email = sr.CharField()
    phone_number = sr.CharField(write_only=True)
    account_type = sr.ChoiceField(choices=ACCOUNT_TYPE)
    password = sr.CharField()

    @staticmethod
    def validate_phone_number(value):
        if not value.startswith('+'):
            raise CustomValidation(
                {
                    "message": "Phone number must start with country code e.g. (+44).",
                    "status": "failed"
                }
            )
        elif not value[1:].isdigit():
            raise CustomValidation({"message": "Phone number must be digits.", "status": "failed"})
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

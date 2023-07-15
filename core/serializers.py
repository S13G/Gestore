import re

from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from rest_framework import serializers as sr
from rest_framework.exceptions import ValidationError

from common.responses import CustomResponse
from core.choices import ACCOUNT_TYPE

User = get_user_model()


class RegisterSerializer(sr.Serializer):
    first_name = sr.CharField()
    last_name = sr.CharField()
    email = sr.CharField()
    phone_number = sr.CharField()
    account_type = sr.ChoiceField(choices=ACCOUNT_TYPE)
    password = sr.CharField()
    confirm_password = sr.CharField()

    @staticmethod
    def validate_email  (value):
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, value):
            raise CustomResponse(code=400, detail="Invalid email. Use the correct email format.")
        return value

    @staticmethod
    def validate_phone_number(value):
        if not value.startswith('+'):
            raise CustomResponse(code=400, detail="Phone number must start with country code e.g. (+44).")
        elif not value[1:].isdigit():
            raise CustomResponse(code=400, detail="Phone number must be digits.")
        return value

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if confirm_password != password:
            raise CustomResponse(code=400, detail="Passwords are not the same, try again.").to_response()
            # Remove 'confirm_password' from validated data
        attrs.pop('confirm_password', None)
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class VerifyEmailSerializer(sr.Serializer):
    email_address = sr.CharField()
    otp = sr.IntegerField()

    @staticmethod
    def validate_email_address(value):
        try:
            validate_email(value)
        except ValidationError:
            raise sr.ValidationError(detail="Invalid email.", code=400)
        return value

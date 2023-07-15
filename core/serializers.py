from django.core.validators import validate_email
from rest_framework import serializers as sr
from rest_framework.exceptions import ValidationError

from common.responses import CustomResponse
from core.choices import ACCOUNT_TYPE


class RegisterSerializer(sr.Serializer):
    first_name = sr.CharField()
    last_name = sr.CharField()
    email_address = sr.CharField()
    phone_number = sr.CharField()
    account_type = sr.ChoiceField(choices=ACCOUNT_TYPE)
    password = sr.CharField()
    confirm_password = sr.CharField()

    @staticmethod
    def validate_email_address(value):
        try:
            validate_email(value)
        except ValidationError:
            raise CustomResponse(code=400, message="Invalid email.").to_response()
        return value

    @staticmethod
    def validate_phone_number(value):
        if not value.startswith('+'):
            raise CustomResponse(code=400, message="Phone number must start with country code e.g (+44).").to_response()
        elif not value[1:].isdigit():
            raise CustomResponse(code=400, message="Phone number must be digits.").to_response()
        return value

    def validate(self, attrs):
        password = self.attrs.get('password')
        confirm_password = self.attrs.get('confirm_password')

        if confirm_password != password:
            raise CustomResponse(code=400, message="Passwords are not the same, try again.").to_response()
        return attrs


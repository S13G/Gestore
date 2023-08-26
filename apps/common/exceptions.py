from django.core.validators import validate_email
from rest_framework import serializers as sr
from rest_framework import status
from rest_framework.exceptions import APIException


class CustomValidation(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "A server error occurred."

    def __init__(self, detail=None, status_code=400):
        if status_code is not None:
            self.status_code = status_code
        if detail is not None:
            self.detail = detail
        else:
            self.detail = {"detail": self.default_detail}


class CustomEmailSerializer(sr.Serializer):
    @staticmethod
    def validate_email(value):
        try:
            validate_email(value)
        except:
            raise CustomValidation({"message": "Invalid email. Use the correct email format.", "status": "failed"})
        return value

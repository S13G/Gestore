from django.db import transaction
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.generics import GenericAPIView

from common.responses import CustomResponse
from core.serializers import RegisterSerializer


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
    def get(self, request):
        with transaction.atomic():
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            data = serializer.data
            response = CustomResponse(code=201, data=data,
                                      message="Registered successfully. Check email for verification code, verification code for phone will be sent after email has been verified")
            return response.to_response()

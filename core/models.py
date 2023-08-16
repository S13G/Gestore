from uuid import uuid4

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from common.models import BaseModel
from core.choices import ACCOUNT_TYPE
from core.managers import CustomUserManager
from core.validators import validate_phone_number


# Create your models here.


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    username = None
    email = models.EmailField(_("Email address"), unique=True)
    account_type = models.CharField(max_length=15, choices=ACCOUNT_TYPE, default=None, null=True)
    email_verified = models.BooleanField(default=False)
    email_changed = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, validators=[validate_phone_number])
    phone_verified = models.BooleanField(default=False)
    email_modified_time = models.DateTimeField(default=None, null=True, editable=False)
    updated = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["phone_number", "first_name", "last_name"]

    objects = CustomUserManager()

    class Meta:
        ordering = ('-date_joined',)

    def __str__(self):
        return self.get_full_name()


class OTPSecret(BaseModel):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="otp_secret", null=True)
    secret = models.CharField(max_length=255, null=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.get_full_name()
from django.db import models
from uuid import uuid4
from django.contrib.auth.models import AbstractUser

from core.choices import ACCOUNT_TYPE
from core.validators import validate_phone_number


# Create your models here.


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    username = None
    email_address = models.EmailField(unique=True)
    account_type = models.CharField(max_length=2, choices=ACCOUNT_TYPE, default=None)
    email_verified = models.BooleanField(default=False)
    email_changed = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, validators=[validate_phone_number])
    phone_verified = models.BooleanField(default=False)

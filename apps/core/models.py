from uuid import uuid4

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from apps.common.models import BaseModel
from apps.core.managers import CustomUserManager
from apps.common.validators import validate_phone_number


# Create your models here.


class User(AbstractUser):
    username = None
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    email = models.EmailField(_("Email address"), unique=True)
    email_verified = models.BooleanField(default=False)
    email_changed = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, validators=[validate_phone_number])
    email_modified_time = models.DateTimeField(default=None, null=True, editable=False)
    is_landlord = models.BooleanField(default=False)
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


class TenantProfile(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="tenant_profile")
    avatar = models.ImageField(upload_to="tenant_avatars")
    date_of_birth = models.DateField()
    emergency_phone_number = models.CharField(max_length=20, validators=[validate_phone_number])
    occupation = models.CharField(max_length=255)
    address = models.CharField(max_length=255)

    @property
    def full_name(self):
        return self.user.get_full_name()

    @property
    def profile_image(self):
        if self.avatar:
            return self.avatar.url
        return None

    def __str__(self):
        return self.user.get_full_name()


class LandLordProfile(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="landlord_profile")
    avatar = models.ImageField(upload_to="LL_avatars")
    date_of_birth = models.DateField()
    occupation = models.CharField(max_length=255)

    @property
    def full_name(self):
        return self.user.get_full_name()

    def profile_image(self):
        if self.avatar:
            return self.avatar.url
        return None

    def __str__(self):
        return self.user.get_full_name()



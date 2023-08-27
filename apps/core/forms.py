# Account creation
from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from apps.common.validators import validate_phone_number
from apps.core.models import User


class CustomUserCreationForm(UserCreationForm):
    phone_number = forms.CharField(max_length=20, validators=[validate_phone_number])

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('email', 'first_name', 'last_name', 'phone_number')


# Account update
class CustomUserChangeForm(UserChangeForm):
    phone_number = forms.CharField(max_length=20, validators=[validate_phone_number])

    class Meta(UserChangeForm.Meta):
        model = User
        fields = ('email', 'first_name', 'last_name', 'phone_number')

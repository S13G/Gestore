# Account creation
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from core.choices import ACCOUNT_TYPE
from core.validators import validate_phone_number

User = get_user_model()


class CustomUserCreationForm(UserCreationForm):
    phone_number = forms.CharField(max_length=20, validators=[validate_phone_number])
    account_type = forms.ChoiceField(choices=ACCOUNT_TYPE)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('email', 'first_name', 'last_name', 'account_type', 'phone_number')


# Account updation
class CustomUserChangeForm(UserChangeForm):
    phone_number = forms.CharField(max_length=20, validators=[validate_phone_number])
    account_type = forms.ChoiceField(choices=ACCOUNT_TYPE)

    class Meta(UserChangeForm.Meta):
        model = User
        fields = ('email', 'first_name', 'last_name', 'account_type', 'phone_number')

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from core.forms import CustomUserChangeForm, CustomUserCreationForm
from core.models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = User
    list_display = (
        "first_name",
        "last_name",
        "email",
        "account_type",
        "phone_verified",
        "email_changed",
        "email_verified",
        "phone_verified",
        "is_staff",
        "is_active",

    )
    list_filter = (
        "first_name",
        "last_name",
        "email",
        "phone_number",
        "is_staff",
        "is_active",
    )
    list_per_page = 20
    fieldsets = (
        (
            "Personal Information",
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "email",
                    "account_type",
                    "phone_number",
                    "password",

                )
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_staff",
                    "is_active",
                    "email_changed",
                    "email_verified",
                    "phone_verified",
                    "groups",
                    "user_permissions"
                )
            },
        ),
    )
    search_fields = ("email", "first_name", "last_name", "phone_number",)
    ordering = ("email", "first_name", "last_name",)

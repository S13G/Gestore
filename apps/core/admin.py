from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from apps.core.forms import CustomUserChangeForm, CustomUserCreationForm
from apps.core.models import *


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


@admin.register(TenantProfile)
class TenantProfileAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Tenant Information",
            {
                "fields": (
                    "avatar",
                    "date_of_birth",
                    "emergency_phone_number",
                    "occupation",
                    "address",
                )
            }
        ),
    )
    list_display = ("full_name", "date_of_birth", "occupation",)
    list_per_page = 20
    list_select_related = ("user",)
    ordering = ("occupation",)
    search_fields = ("occupation", "date_of_birth", "full_name",)

    @admin.display(ordering="user")
    def full_name(self, obj: TenantProfile):
        return obj.user.get_full_name()


@admin.register(LandLordProfile)
class LandLordProfileAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Tenant Information",
            {
                "fields": (
                    "avatar",
                    "date_of_birth",
                    "occupation",
                )
            }
        ),
    )
    list_display = ("full_name", "date_of_birth", "occupation",)
    list_per_page = 20
    list_select_related = ("user",)
    ordering = ("occupation",)
    search_fields = ("occupation", "date_of_birth", "full_name",)

    @admin.display(ordering="user")
    def full_name(self, obj: TenantProfile):
        return obj.user.get_full_name()

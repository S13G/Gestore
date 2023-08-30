from django.contrib import admin

from apps.property.models import Property


# Register your models here.
@admin.register(Property)
class PropertyAdmin(admin.ModelAdmin):
    pass

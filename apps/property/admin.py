from urllib.parse import urlencode

from django.contrib import admin
from django.contrib.admin import TabularInline
from django.db.models import Count
from django.urls import reverse
from django.utils.html import format_html

from apps.property.models import PropertyType, PropertyFacility, PublicFacility, Property, PropertyImage, \
    PropertyReview


# Register your models here.
@admin.register(PropertyType)
class PropertyTypeAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Type Information",
            {
                "fields":
                    (
                        "type",
                    )
            }
        ),
    )
    list_display = ('type', 'properties_count', 'created', 'updated',)
    list_per_page = 20
    ordering = ('type',)
    search_fields = ('type',)

    @admin.display(ordering="properties_count")
    def properties_count(self, property_type):
        url = (reverse("admin:property_property_changelist")
               + "?"
               + urlencode({"property_type__id": str(property_type.id)})
               )
        return format_html('<a href="{}">{} Properties</a>', url, property_type.properties_count)

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(properties_count=Count("properties"))


@admin.register(PropertyFacility)
class PropertyFacilityAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Facility Information",
            {
                "fields":
                    (
                        "name",
                    )
            }
        ),
    )
    list_display = ('name', 'created', 'updated',)
    list_per_page = 20
    ordering = ('name',)
    search_fields = ('name',)


@admin.register(PublicFacility)
class PublicFacilityAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Facility Information",
            {
                "fields":
                    (
                        "name",
                    )
            }
        ),
    )
    list_display = ('name', 'created', 'updated',)
    list_per_page = 20
    ordering = ('name',)
    search_fields = ('name',)


class PropertyImageInline(TabularInline):
    max_num = 11
    model = PropertyImage
    extra = 1


@admin.register(Property)
class PropertyAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Property Information",
            {
                "fields":
                    (
                        "property_owner",
                        "type",
                        "name",
                        "rooms",
                        "address",
                        "country",
                        "home_facilities",
                        "public_facilities",
                        "about",
                        "advance_payment",
                        "full_payment",
                        "intro_video",
                        "rented",
                    )
            }
        ),
    )
    inlines = (PropertyImageInline,)
    list_display = ('owner', 'property_name', 'rooms', 'country', 'advance_payment', 'full_payment', 'rented',)
    list_per_page = 20
    list_select_related = ('property_owner', 'type',)
    ordering = ('name', 'rooms', 'country',)
    search_fields = ('name', 'country', 'advance_payment', 'full_payment',)

    @staticmethod
    @admin.display(ordering='property_owner')
    def owner(obj: Property):
        return obj.property_owner.get_full_name()

    @staticmethod
    @admin.display(ordering='name')
    def property_name(obj: Property):
        max_length = 40
        if len(obj.name) > max_length:
            return obj.name[:max_length]
        return obj.name


@admin.register(PropertyReview)
class PropertyReviewAdmin(admin.ModelAdmin):
    fieldsets = (
        (
            "Facility Information",
            {
                "fields":
                    (
                        "user",
                        "property",
                        "stars",
                        "description",
                    )
            }
        ),
    )
    list_display = ('reviewer_name', 'property_name', 'stars',)
    list_per_page = 20
    list_select_related = ('user', 'property',)
    ordering = ('stars', 'property__name',)
    search_fields = ('property__name', 'stars')

    @staticmethod
    @admin.display(ordering="user")
    def reviewer_name(obj: PropertyReview):
        return obj.user.get_full_name()

    @staticmethod
    @admin.display(ordering="property")
    def property_name(obj: PropertyReview):
        max_length = 30
        if len(obj.property.name) > max_length:
            return obj.property.name[:max_length]
        return obj.property.name

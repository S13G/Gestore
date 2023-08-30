from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator
from django.db import models
from django_countries.fields import CountryField

from apps.common.models import BaseModel

User = get_user_model()


# Create your models here.
class PropertyType(BaseModel):
    type = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.type


class PropertyFacility(BaseModel):
    name = models.CharField(max_length=255)

    class Meta:
        verbose_name_plural = "Property Facilities"

    def __str__(self):
        return self.name


class PublicFacility(BaseModel):
    name = models.CharField(max_length=255)

    class Meta:
        verbose_name_plural = "Public Facilities"

    def __str__(self):
        return self.name


class Property(BaseModel):
    property_owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_properties", null=True)
    name = models.CharField(max_length=255, unique=True)
    rooms = models.PositiveIntegerField(default=0)
    address = models.CharField(max_length=255)
    country = CountryField()
    home_facilities = models.ManyToOneRel(on_delete=models.DO_NOTHING, related_name="property")
    public_facilities = models.ManyToOneRel(on_delete=models.DO_NOTHING, related_name="property")
    about = models.TextField()
    advance_payment = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    full_payment = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    intro_video = models.FileField(upload_to="intro_videos", null=True, blank=True)

    def __str__(self):
        return f"{self.property_owner.get_full_name()} ---- {self.name}"


class PropertyImage(BaseModel):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name="property_images")
    image = models.ImageField(upload_to="property_images")

    def image_url(self):
        if self.image:
            return self.image.url
        return None

    def __str__(self):
        return self.property.name


class PropertyReview(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="property_reviews", null=True)
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name="reviews", null=True)
    stars = models.PositiveIntegerField(null=True)
    description = models.TextField()

    def __str__(self):
        return f"{self.user.get_full_name()} -- {self.property.name} -- {self.stars}"


class FavouriteProperty(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="favourite_properties", null=True)
    property = models.ForeignKey(Property, on_delete=models.CASCADE, null=True)

    def __str__(self):
        return f"{self.user.get_full_name()} -- {self.property.name}"

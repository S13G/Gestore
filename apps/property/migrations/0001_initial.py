# Generated by Django 4.2.3 on 2023-08-31 07:22

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import django_countries.fields
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Property',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True, null=True)),
                ('name', models.CharField(max_length=255, unique=True)),
                ('rooms', models.PositiveIntegerField(default=0)),
                ('address', models.CharField(max_length=255)),
                ('country', django_countries.fields.CountryField(max_length=2)),
                ('about', models.TextField()),
                ('advance_payment', models.DecimalField(decimal_places=2, max_digits=10, validators=[django.core.validators.MinValueValidator(0)])),
                ('full_payment', models.DecimalField(decimal_places=2, max_digits=10, validators=[django.core.validators.MinValueValidator(0)])),
                ('intro_video', models.FileField(blank=True, null=True, upload_to='intro_videos')),
            ],
            options={
                'ordering': ('-created',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PropertyFacility',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True, null=True)),
                ('name', models.CharField(max_length=255)),
            ],
            options={
                'verbose_name_plural': 'Property Facilities',
            },
        ),
        migrations.CreateModel(
            name='PropertyType',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True, null=True)),
                ('type', models.CharField(max_length=255, unique=True)),
            ],
            options={
                'ordering': ('-created',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PublicFacility',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True, null=True)),
                ('name', models.CharField(max_length=255)),
            ],
            options={
                'verbose_name_plural': 'Public Facilities',
            },
        ),
        migrations.CreateModel(
            name='PropertyReview',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True, null=True)),
                ('stars', models.PositiveIntegerField(null=True)),
                ('description', models.TextField()),
                ('property', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='reviews', to='property.property')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='property_reviews', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-created',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PropertyImage',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True, null=True)),
                ('image', models.ImageField(upload_to='property_images')),
                ('property', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='property_images', to='property.property')),
            ],
            options={
                'ordering': ('-created',),
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='property',
            name='home_facilities',
            field=models.ManyToManyField(to='property.propertyfacility'),
        ),
        migrations.AddField(
            model_name='property',
            name='property_owner',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='owned_properties', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='property',
            name='public_facilities',
            field=models.ManyToManyField(to='property.publicfacility'),
        ),
        migrations.CreateModel(
            name='FavouriteProperty',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True, null=True)),
                ('property', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='property.property')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='favourite_properties', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-created',),
                'abstract': False,
            },
        ),
    ]

# Generated by Django 4.2.3 on 2023-07-15 10:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_otpsecret'),
    ]

    operations = [
        migrations.DeleteModel(
            name='OTPSecret',
        ),
    ]

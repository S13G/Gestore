# Generated by Django 4.2.3 on 2023-08-26 00:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0008_alter_otpsecret_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_landlord',
            field=models.BooleanField(default=False),
        ),
    ]

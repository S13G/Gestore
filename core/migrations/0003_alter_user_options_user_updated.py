# Generated by Django 4.2.3 on 2023-07-15 09:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_alter_user_account_type'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='user',
            options={'ordering': ('-date_joined',)},
        ),
        migrations.AddField(
            model_name='user',
            name='updated',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
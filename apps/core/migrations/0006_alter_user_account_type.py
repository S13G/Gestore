# Generated by Django 4.2.3 on 2023-08-15 21:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_delete_otpsecret'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_type',
            field=models.CharField(choices=[('Tenant', 'Tenant'), ('Landlord', 'Landlord')], default=None, max_length=15, null=True),
        ),
    ]

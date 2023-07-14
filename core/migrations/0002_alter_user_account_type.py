# Generated by Django 4.2.3 on 2023-07-14 16:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_type',
            field=models.CharField(choices=[('TA', 'Tenant'), ('LA', 'Landlord')], default=None, max_length=2, null=True),
        ),
    ]

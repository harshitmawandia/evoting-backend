# Generated by Django 4.2 on 2023-04-20 02:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('electorate', '0003_delete_tokentootp'),
    ]

    operations = [
        migrations.AlterField(
            model_name='voter',
            name='otpGenerated',
            field=models.BooleanField(default=False),
        ),
    ]

# Generated by Django 4.2 on 2023-04-20 10:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('electorate', '0004_alter_voter_otpgenerated'),
    ]

    operations = [
        migrations.RenameField(
            model_name='vote',
            old_name='C_rid',
            new_name='C_ridX',
        ),
        migrations.AddField(
            model_name='vote',
            name='C_ridY',
            field=models.DecimalField(decimal_places=0, default=0, max_digits=300),
            preserve_default=False,
        ),
    ]
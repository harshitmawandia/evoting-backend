# Generated by Django 4.2 on 2023-04-19 20:48

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('electorate', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=4)),
                ('validFrom', models.DateTimeField(auto_now_add=True)),
                ('booth', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.booth', unique=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='token',
            name='booth',
        ),
        migrations.RemoveField(
            model_name='token',
            name='otp',
        ),
        migrations.RemoveField(
            model_name='token',
            name='validFrom',
        ),
        migrations.RemoveField(
            model_name='voter',
            name='voteCasted',
        ),
        migrations.AddField(
            model_name='election',
            name='votesPerVoter',
            field=models.IntegerField(default=1),
        ),
        migrations.AddField(
            model_name='token',
            name='C_rid',
            field=models.DecimalField(decimal_places=0, default=0, max_digits=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='token',
            name='C_u',
            field=models.DecimalField(decimal_places=0, default=0, max_digits=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='voter',
            name='numVotesCasted',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='voter',
            name='otpGenerated',
            field=models.CharField(default=None, max_length=4),
        ),
        migrations.CreateModel(
            name='OTP_To_Token',
            fields=[
                ('token', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='electorate.token', unique=True)),
                ('otp', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.otp')),
            ],
        ),
    ]

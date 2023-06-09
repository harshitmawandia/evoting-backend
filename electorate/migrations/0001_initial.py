# Generated by Django 4.2 on 2023-04-20 01:53

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Booth',
            fields=[
                ('ip', models.GenericIPAddressField(protocol='IPv4', unique=True)),
                ('id', models.AutoField(primary_key=True, serialize=False, unique=True)),
                ('verified', models.BooleanField(default=False)),
                ('status', models.CharField(choices=[('Empty', 'Empty'), ('Token Generated', 'Token Generated'), ('Token Verified', 'Token Verified')], default='Empty', max_length=15)),
            ],
        ),
        migrations.CreateModel(
            name='Election',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('electionName', models.CharField(max_length=50, unique=True)),
                ('electionDate', models.DateField()),
                ('electionTimeStart', models.TimeField()),
                ('electionTimeEnd', models.TimeField()),
                ('electionStatus', models.BooleanField(default=False)),
                ('numberOfCandidates', models.IntegerField(default=0)),
                ('votesPerVoter', models.IntegerField(default=1)),
            ],
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('entryNumber', models.CharField(max_length=15, primary_key=True, serialize=False, unique=True)),
                ('name', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rid', models.DecimalField(decimal_places=0, max_digits=300)),
                ('C_ridX', models.DecimalField(decimal_places=0, max_digits=300)),
                ('C_ridY', models.DecimalField(decimal_places=0, max_digits=300)),
                ('r_rid', models.DecimalField(decimal_places=0, max_digits=300)),
                ('u', models.DecimalField(decimal_places=0, max_digits=300)),
                ('C_uX', models.DecimalField(decimal_places=0, max_digits=300)),
                ('C_uY', models.DecimalField(decimal_places=0, max_digits=300)),
                ('r_u', models.DecimalField(decimal_places=0, max_digits=300)),
            ],
        ),
        migrations.CreateModel(
            name='Otptotoken',
            fields=[
                ('token', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='electorate.token', unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Voter',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otpGenerated', models.CharField(default='', max_length=4)),
                ('otpVerified', models.BooleanField(default=False)),
                ('numVotesCasted', models.IntegerField(default=0)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.election')),
                ('entryNumber', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.profile')),
            ],
        ),
        migrations.CreateModel(
            name='Vote',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('C_rid', models.DecimalField(decimal_places=0, max_digits=300)),
                ('C_vX', models.DecimalField(decimal_places=0, max_digits=300)),
                ('C_vY', models.DecimalField(decimal_places=0, max_digits=300)),
                ('rid', models.DecimalField(decimal_places=0, max_digits=300)),
                ('v', models.DecimalField(decimal_places=0, max_digits=300)),
                ('r_rid', models.DecimalField(decimal_places=0, max_digits=300)),
                ('r_v', models.DecimalField(decimal_places=0, max_digits=300)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.election')),
            ],
        ),
        migrations.AddField(
            model_name='token',
            name='voter',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.voter'),
        ),
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=4)),
                ('validFrom', models.DateTimeField(auto_now_add=True)),
                ('booth', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.booth', unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Candidate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('j', models.IntegerField(default=0)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.election', to_field='electionName')),
                ('entryNumber', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.profile')),
            ],
        ),
        migrations.AddConstraint(
            model_name='voter',
            constraint=models.UniqueConstraint(fields=('entryNumber', 'election'), name='unique_electorate'),
        ),
        migrations.AddField(
            model_name='otptotoken',
            name='otp',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='electorate.otp'),
        ),
        migrations.AddConstraint(
            model_name='candidate',
            constraint=models.UniqueConstraint(fields=('entryNumber', 'election'), name='unique_candidate'),
        ),
    ]

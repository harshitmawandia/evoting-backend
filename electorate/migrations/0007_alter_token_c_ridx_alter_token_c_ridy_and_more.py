# Generated by Django 4.2 on 2023-04-21 04:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('electorate', '0006_alter_token_rid_alter_vote_v'),
    ]

    operations = [
        migrations.AlterField(
            model_name='token',
            name='C_ridX',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='token',
            name='C_ridY',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='token',
            name='C_uX',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='token',
            name='C_uY',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='token',
            name='r_rid',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='token',
            name='r_u',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='token',
            name='rid',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='token',
            name='u',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='vote',
            name='C_ridX',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='vote',
            name='C_ridY',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='vote',
            name='C_vX',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='vote',
            name='C_vY',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='vote',
            name='r_rid',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='vote',
            name='r_v',
            field=models.CharField(default='', max_length=300),
        ),
        migrations.AlterField(
            model_name='vote',
            name='rid',
            field=models.CharField(default='', max_length=300),
        ),
    ]

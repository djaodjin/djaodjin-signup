# Generated by Django 3.2.20 on 2023-09-12 13:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('signup', '0009_v0_8_0'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='contact',
            name='otc_backend',
        ),
        migrations.AddField(
            model_name='contact',
            name='email_code',
            field=models.IntegerField(null=True,
                verbose_name='Email verification code'),
        ),
        migrations.AddField(
            model_name='contact',
            name='phone_code',
            field=models.IntegerField(null=True,
                verbose_name='Phone verification code'),
        ),
    ]

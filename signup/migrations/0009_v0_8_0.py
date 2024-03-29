# Generated by Django 3.2.18 on 2023-04-05 22:08

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('signup', '0008_v0_6_0'),
    ]

    operations = [
        migrations.RenameField(
            model_name='credentials',
            old_name='api_priv_key',
            new_name='api_password',
        ),
        migrations.RenameField(
            model_name='contact',
            old_name='mfa_priv_key',
            new_name='one_time_code',
        ),
        migrations.RenameField(
            model_name='contact',
            old_name='mfa_nb_attempts',
            new_name='otc_nb_attempts',
        ),
        migrations.RenameField(
            model_name='contact',
            old_name='mfa_backend',
            new_name='otc_backend',
        ),
        migrations.AlterField(
            model_name='contact',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='contacts', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='OTPGenerator',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('priv_key', models.CharField(max_length=40, null=True, verbose_name='Private key for the OTP generator')),
                ('nb_attempts', models.IntegerField(default=0, verbose_name='Number of attempts to pass the OTP code')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='otp', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]

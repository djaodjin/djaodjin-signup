from __future__ import unicode_literals

import django.core.validators
from django.db import migrations, models
import signup.models


class Migration(migrations.Migration):

    dependencies = [
        ('signup', '0007_v0_4_8'),
    ]

    operations = [
        migrations.CreateModel(
            name='DelegateAuth',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(help_text='fully qualified domain name at which the site is available', max_length=100, unique=True, validators=[signup.models.domain_name_validator, django.core.validators.RegexValidator('([a-z\u00a1-\uffff0-9](?:[a-z\u00a1-\uffff0-9-]{0,61}[a-z\u00a1-\uffff0-9])?(?:\\.(?!-)[a-z\u00a1-\uffff0-9-]{1,63}(?<!-))*\\.(?!-)(?:[a-z\u00a1-\uffff-]{2,63}|xn--[a-z0-9]{1,59})(?<!-)\\.?|localhost)', "Enter a valid 'domain', ex: example.com", 'invalid')])),
                ('provider', models.CharField(max_length=32)),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='Date/time of creation (in ISO format)')),
            ],
        ),
    ]

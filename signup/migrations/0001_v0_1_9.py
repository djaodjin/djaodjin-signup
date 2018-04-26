# -*- coding: utf-8 -*-
# Generated by Django 1.9.9 on 2018-04-26 03:14
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Activity',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('text', models.TextField(blank=True)),
                ('extra', models.TextField(null=True)),
                ('account', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='activities', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Contact',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slug', models.SlugField(help_text='Unique identifier shown in the URL bar.', unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('full_name', models.CharField(blank=True, max_length=60, verbose_name='Full name')),
                ('nick_name', models.CharField(blank=True, max_length=60, verbose_name='Nick name')),
                ('verification_key', models.CharField(max_length=40, verbose_name='email verification key')),
                ('extra', models.TextField(null=True)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slug', models.SlugField(help_text='Unique identifier.', unique=True)),
                ('users', models.ManyToManyField(related_name='notifications', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='activity',
            name='contact',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='signup.Contact'),
        ),
        migrations.AddField(
            model_name='activity',
            name='created_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
        ),
    ]
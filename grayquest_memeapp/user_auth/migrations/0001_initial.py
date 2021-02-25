# Generated by Django 3.1.2 on 2021-02-25 12:21

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
            name='user_cookie_consent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cookie_consent', models.BooleanField(default=None, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_User', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user_cookie_consent',
                'db_table': 'user_cookie_consent',
            },
        ),
    ]

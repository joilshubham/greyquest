from django.db import models
from django.contrib.auth.models import User
from datetime import datetime

class user_cookie_consent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name='user_User', blank=True, null=True)
    cookie_consent = models.BooleanField(default=None, blank=False, null=True)
    date= models.DateTimeField(default=datetime.now(), blank=True, null=True)


    class Meta:
        verbose_name = 'user_cookie_consent'
        db_table = 'user_cookie_consent'

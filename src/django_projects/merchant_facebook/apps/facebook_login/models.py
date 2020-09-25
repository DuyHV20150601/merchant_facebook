from django.db import models


# Create your models here.
class User(models.Model):
    user_id = models.CharField(max_length=50)
    username = models.CharField(max_length=100)
    user_access_token = models.TextField(max_length=1000)

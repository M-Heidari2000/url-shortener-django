from django.db import models
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site

# Create your models here.

class URLMap(models.Model):
    long_url = models.URLField(max_length=500)
    alias = models.CharField(max_length=10, unique=True)
    mobile_clicks = models.IntegerField(default=0)
    desktop_clicks = models.IntegerField(default=0)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name='urls')

    def get_short_url(self, request):
        return 'http://' + get_current_site(request).domain + '/' + self.alias 

    def __str__(self):
        return self.alias

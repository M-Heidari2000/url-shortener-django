from django.contrib import admin
from .models import URLMap
# Register your models here.

class URLMapAdmin(admin.ModelAdmin):
    list_display = ('alias', 'mobile_clicks', 'desktop_clicks', 'owner')
    list_filter = ('owner', 'mobile_clicks', 'desktop_clicks')

admin.site.register(URLMap, URLMapAdmin)

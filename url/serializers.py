from rest_framework import serializers
from .models import URLMap

class URLMapSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLMap
        fields = ('long_url', )


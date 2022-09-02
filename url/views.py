from django.shortcuts import render, redirect, reverse
from .models import URLMap
from django.http import Http404, JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sites.shortcuts import get_current_site
from django.views import View
import random
import re
from rest_framework.generics import CreateAPIView, UpdateAPIView, DestroyAPIView, ListAPIView
from rest_framework.views import APIView
from .serializers import URLMapSerializer
from django.utils.decorators import method_decorator

# Create your views here.

characters = [chr(i) for i in range(65, 123) if i not in range(91, 97)]
digits = [str(i) for i in range(1, 10)]
characters.extend(digits)

@method_decorator(csrf_exempt, name='dispatch')
class LongURLView(CreateAPIView):
    
    queryset = URLMap.objects.all()
    serializer_class = URLMapSerializer

    def post(self, request):
        try:
            long_url = request.POST.get('long_url') 
            user = request.user
            length = random.randint(1, 10)
            alias = ''.join(random.choices(characters, k=length))
            url_map = URLMap(long_url=long_url, alias=alias)
            if user.is_authenticated:
                try:
                    url_map = URLMap.objects.get(long_url=long_url, owner=user)
                    response = {'alias': url_map.alias, 'short_url': url_map.get_short_url(request)}
                    return JsonResponse(response)
                except:
                    url_map.owner = user
                    url_map.save()
                    response = {'alias': url_map.alias, 'short_url': url_map.get_short_url(request)}
                    return JsonResponse(response)
            else:
                url_map.save()
                response = {'alias': url_map.alias, 'short url': url_map.get_short_url(request)}
                return JsonResponse(response)
        except:
            response = {'status': 'Failed', 'message': 'Something went wrong'}
            return JsonResponse(response, status=400)
    

class ShortURLView(APIView):

    queryset = URLMap.objects.all()
    serializer_class = URLMapSerializer

    def get(self, request, alias):
        if request.method == 'GET' and alias != '':
            url_map = URLMap.objects.get(alias=alias)
            long_url = url_map.long_url
            if request.user_agent.is_mobile:
                url_map.mobile_clicks += 1
            else:
                url_map.desktop_clicks += 1
            url_map.save()
            return redirect(long_url)

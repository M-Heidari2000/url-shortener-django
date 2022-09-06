from django.shortcuts import render
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import login, authenticate, logout
from ipware import get_client_ip
from url.models import URLMap
from django.views import View
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, UpdateAPIView, DestroyAPIView, ListAPIView
from .serializers import UserSerializer
from django.contrib.auth.models import User
from django.utils.decorators import method_decorator
import logging

logger = logging.getLogger('my_logger')

def generate_log(request, status_code='', response=''):
    method = request.method
    ip, _ = get_client_ip(request)
    os = request.method.os.family
    end_point = request.get_absolute.uri()
    browser = request.users_agent.browser.family

    log_info = {
        'url': end_point,
        'request_method': method,
        'user_ip': ip,
        'operating_system': os,
        'browser': browser,
    }
    return log_info

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(CreateAPIView):
    
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def post(self, request):
        try:
            form = UserCreationForm(request.POST)
            if form.is_valid:
                user = form.save()
                user.save()
                response = {'status': 'successful', 'message': 'Registration successful'}
                logger.debug(request, 200, response)
                return JsonResponse(response)
        except:
            response = {'status': 'failed', 'message': 'Registration failed. Invalid information'}
            logger.debug(request, 400, response)
            return JsonResponse(response, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def post(self, request):
        logger.info('post request login')
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                response = {'status': 'successful', 'message': f'logged in as {username}'}
                logger.debug(request, 200, response)
                return JsonResponse(response)
            else:
                response = {'status': 'failed', 'message': 'Invalid username or password'}
                logger.debug(request, 400, response)
                return JsonResponse(response, status=400)
        else:
            response = {'status': 'failed', 'message': 'Invalid username or password'}
            logger.debug(request, 400, response)
            return JsonResponse(response, status=400)


class LogoutView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get(self, request):
        try:
            logout(request)
            response = {'status': 'successful', 'message': 'Logged out'}
            logger.debug(request, 200, response)
            return JsonResponse(response)
        except:
            response = {'status': 'failed', 'message': 'Something went wrong'}
            logger.debug(request, 400, response)
            return JsonResponse(response, status=400)


class WhoAmIView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get(self, request):
        user = request.user
        ip, is_routable = get_client_ip(request)
        info = {}
        info['username'] = 'Anonymous user' if user.username == '' else user.username
        info['ip address'] = 'unknown' if ip is None else ip
        logger.debug(request, 200, response)
        return JsonResponse(info)


class GetMyURLsView(ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get(self, request):
        user = request.user
        if user.is_authenticated:
            url_maps = user.urls.all()
            response = [{'short url': u.get_short_url(request), 'long url': u.long_url, 
                         'mobile clicks': u.mobile_clicks, 'desktop clicks':u.desktop_clicks} for u in url_maps]
            logger.debug(request, 200, response)
            return JsonResponse(response, safe=False)
        else:
            response = {'status': 'failed', 'message': 'Register to access to urls'}
            logger.debug(request, 400, response)
            return JsonResponse(response, status=400)



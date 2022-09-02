from django.urls import path
from . import views

urlpatterns = [
    path('create', views.LongURLView.as_view(), name='long_url_handler'),
    path('<path:alias>', views.ShortURLView.as_view(), name='short_url_handler'),
]

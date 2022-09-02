from django.urls import path
from . import views

urlpatterns = [
    path('register', views.RegisterView.as_view(), name='register'),
    path('login', views.LoginView.as_view(), name='login'),
    path('logout', views.LogoutView.as_view(), name='logout'),
    path('whoami', views.WhoAmIView.as_view(), name='whoami'),
    path('get-my-urls', views.GetMyURLsView.as_view(), name='get-my-urls'),
]

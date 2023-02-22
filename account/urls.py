from django.urls import path
from account.views import register, login

urlpatterns = [
    path('register', register, name='user_register'),
    path('login', login, name='user_login'),
]

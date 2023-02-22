from django.urls import path
from account.views import register

urlpatterns = [
    path('register', register, name='user_register'),
]

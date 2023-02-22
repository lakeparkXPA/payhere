from django.urls import path
from account.views import register, login, logout

urlpatterns = [
    path('register', register, name='user_register'),
    path('login', login, name='user_login'),
    path('logout', logout, name='user_logout')
]

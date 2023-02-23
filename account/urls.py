from django.urls import path
from account.views import register, login, logout, Book

urlpatterns = [
    path('register', register, name='user_register'),
    path('login', login, name='user_login'),
    path('logout', logout, name='user_logout'),
    path('book', Book.as_view(), name='book'),
]

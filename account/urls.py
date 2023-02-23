from django.urls import path
from account.views import register, login, logout, Book, abook_detail

urlpatterns = [
    path('register', register, name='user_register'),
    path('login', login, name='user_login'),
    path('logout', logout, name='user_logout'),
    path('book', Book.as_view(), name='book'),
    path('detail', abook_detail, name='detail'),
]

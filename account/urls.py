from django.urls import path
from account.views import register, login, logout, Book, abook_detail, abook_detail_duplicate, abook_share, \
    abook_detail_share

urlpatterns = [
    path('register', register, name='register'),
    path('login', login, name='login'),
    path('logout', logout, name='user_logout'),
    path('book', Book.as_view(), name='book'),
    path('detail', abook_detail, name='detail'),
    path('duplicate', abook_detail_duplicate, name='duplicate'),
    path('share', abook_share, name='share'),
    path('dshare', abook_detail_share, name='dshare'),
]

from django.urls import path
from account.views import Register, Login, Logout, Book, abook_detail, abook_detail_duplicate, abook_share, \
    abook_detail_share

urlpatterns = [
    path('register', Register.as_view(), name='register'),
    path('login', Login.as_view(), name='login'),
    path('logout', Logout.as_view(), name='logout'),
    path('book', Book.as_view(), name='book'),
    path('detail', abook_detail, name='detail'),
    path('duplicate', abook_detail_duplicate, name='duplicate'),
    path('share', abook_share, name='share'),
    path('dshare', abook_detail_share, name='dshare'),
]

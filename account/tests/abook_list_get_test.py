from rest_framework.test import APITestCase
from rest_framework.views import status

from django.urls import reverse

from http.cookies import SimpleCookie

from account.models import User, Abook

import bcrypt


class AbookGetTestCase(APITestCase):
    def setUp(self):
        self.url1 = reverse('book')
        self.url2 = reverse('login')
        self.user1 = User.objects.create(email="test1@gmail.com",
                                         password=bcrypt.hashpw("12345".encode('utf-8'), bcrypt.gensalt()).decode(
                                             'utf-8'))
        self.user2 = User.objects.create(email="test2@gmail.com",
                                         password=bcrypt.hashpw("12345".encode('utf-8'), bcrypt.gensalt()).decode(
                                             'utf-8'))
        self.abook1 = Abook.objects.create(user=self.user1, amount=10000, memo='test1')
        self.abook2 = Abook.objects.create(user=self.user1, amount=20000, memo='test2')

        self.data1 = {"email": "test1@gmail.com", "password": "12345"}


    def test_abook_get_success(self):
        response = self.client.post(self.url2, data=self.data1, format='json')

        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        self.client.cookies = SimpleCookie(response.cookies)

        response = self.client.get(self.url1, **header)
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_no_token_error(self):
        response = self.client.get(self.url1)
        self.assertEqual(status.HTTP_401_UNAUTHORIZED, response.status_code)
        self.assertEqual('Authentication credentials were not provided.', response.data['detail'])


from rest_framework.test import APITestCase
from rest_framework.views import status

from django.urls import reverse

from http.cookies import SimpleCookie

from account.models import User, Abook

import bcrypt
import datetime
from pytz import timezone


class AbookGetDetailTestCase(APITestCase):
    def setUp(self):
        self.url1 = reverse('detail')
        self.url2 = reverse('login')
        self.user = User.objects.create(email="test@gmail.com",
                                        password=bcrypt.hashpw("12345".encode('utf-8'), bcrypt.gensalt()).decode(
                                            'utf-8'))
        self.abook = Abook.objects.create(user=self.user, abook_time=datetime.datetime.now(timezone('Asia/Seoul')),
                                          amount=10000, memo='test')

        self.data = {"email": "test@gmail.com", "password": "12345"}


    def test_abook_get_detail_success(self):
        response = self.client.post(self.url2, data=self.data, format='json')

        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        self.client.cookies = SimpleCookie(response.cookies)

        response = self.client.get(self.url1 + '?aid=1', **header)
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_no_token_error(self):
        response = self.client.get(self.url1 + '?aid=1')
        self.assertEqual(status.HTTP_403_FORBIDDEN, response.status_code)
        self.assertEqual('Authentication credentials were not provided.', response.data['detail'])

    def test_no_id_error(self):
        response = self.client.post(self.url2, data=self.data, format='json')

        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        self.client.cookies = SimpleCookie(response.cookies)

        response = self.client.get(self.url1, **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)

    def test_wrong_id_error(self):
        response = self.client.post(self.url2, data=self.data, format='json')

        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        self.client.cookies = SimpleCookie(response.cookies)

        response = self.client.get(self.url1 + '?aid=100', **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
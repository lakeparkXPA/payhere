from rest_framework.test import APITestCase
from rest_framework.views import status
from django.urls import reverse

from account.models import User, Abook

import bcrypt
import datetime
from pytz import timezone


class AbookShareDetailTestCase(APITestCase):
    def setUp(self):
        self.url1 = reverse('share')
        self.url2 = reverse('dshare')
        self.url3 = reverse('login')
        self.user = User.objects.create(email="test@gmail.com",
                                        password=bcrypt.hashpw("12345".encode('utf-8'), bcrypt.gensalt()).decode(
                                            'utf-8'))
        self.abook = Abook.objects.create(abook_id=1, user=self.user, abook_time=datetime.datetime.now(timezone('Asia/Seoul')),
                                          amount=10000, memo='test')

        self.data = {"email": "test@gmail.com", "password": "12345"}


    def test_abook_share_detail_success(self):
        response = self.client.post(self.url3, data=self.data, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.get(self.url1 + '?aid=1', **header)
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_no_token_error(self):
        response = self.client.get(self.url1 + '?aid=1')
        self.assertEqual(status.HTTP_403_FORBIDDEN, response.status_code)
        self.assertEqual('Authentication credentials were not provided.', response.data['detail'])

    def test_no_id_error(self):
        response = self.client.post(self.url3, data=self.data, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.get(self.url1, **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)

    def test_wrong_id_error(self):
        response = self.client.post(self.url3, data=self.data, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.get(self.url1 + '?aid=100', **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)

    def test_abook_shared_detail_success(self):
        response = self.client.post(self.url3, data=self.data, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.get(self.url2 + '?aid=1', **header)
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_shared_detail_no_id_error(self):
        response = self.client.post(self.url3, data=self.data, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.get(self.url2, **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)

    def test_shared_detail_wrong_id_error(self):
        response = self.client.post(self.url3, data=self.data, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.get(self.url2 + '?aid=100', **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
from rest_framework.test import APITestCase
from rest_framework.views import status
from django.urls import reverse

from account.models import User, Abook

import bcrypt
import datetime
from pytz import timezone


class AbookDetailDuplicateTestCase(APITestCase):
    def setUp(self):
        self.url1 = reverse('duplicate')
        self.url2 = reverse('login')
        self.user = User.objects.create(email="test@gmail.com",
                                        password=bcrypt.hashpw("12345".encode('utf-8'), bcrypt.gensalt()).decode(
                                            'utf-8'))
        self.abook = Abook.objects.create(user=self.user, abook_time=datetime.datetime.now(timezone('Asia/Seoul')),
                                          amount=10000, memo='test')
        self.data1 = {"abook_id": 1}
        self.data2 = {}
        self.data3 = {"abook_id": 100}
        self.data4 = {"email": "test@gmail.com", "password": "12345"}


    def test_abook_detail_duplicate_success(self):
        response = self.client.post(self.url2, data=self.data4, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.post(self.url1, data=self.data1, format='json', **header)
        self.assertEqual(status.HTTP_200_OK, response.status_code)

    def test_no_token_error(self):
        response = self.client.post(self.url1, data=self.data1, format='json')
        self.assertEqual(status.HTTP_403_FORBIDDEN, response.status_code)
        self.assertEqual('Authentication credentials were not provided.', response.data['detail'])

    def test_no_id_error(self):
        response = self.client.post(self.url2, data=self.data4, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.post(self.url1, data=self.data2, format='json', **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)

    def test_wrong_id_error(self):
        response = self.client.post(self.url2, data=self.data4, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.post(self.url1, data=self.data3, format='json', **header)
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)


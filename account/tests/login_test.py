from rest_framework.test import APITestCase, APIClient
from rest_framework.views import status
from django.urls import reverse

from account.models import User
import bcrypt

class LoginTestCase(APITestCase):
    def setUp(self):
        self.url = reverse('user_login')
        self.user = User.objects.create(user_id=1, email="test@gmail.com", password=bcrypt.hashpw("12345".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'))
        self.data1 = {"email": "test@gmail.com", "password": "12345"}
        self.data2 = {"email": "test1@gmail.com", "password": "12345"}
        self.data3 = {"email": "test", "password": "12345"}
        self.data4 = {"email": "test@gmail.com", "password": "54321"}


    def test_login_success(self):
        response = self.client.post(self.url, data=self.data1, format='json')
        self.assertEqual(status.HTTP_202_ACCEPTED, response.status_code)


    def test_login_wrong_email_error(self):
        response = self.client.post(self.url, data=self.data2, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('wrong_email', response.data['code'])

    def test_login_email_format_error(self):
        response = self.client.post(self.url, data=self.data3, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('email_format', response.data['code'])

    def test_login_wrong_password_error(self):
        response = self.client.post(self.url, data=self.data4, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('wrong_password', response.data['code'])

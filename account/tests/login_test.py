from rest_framework.test import APITestCase
from rest_framework.views import status
from django.urls import reverse

from account.models import User
import bcrypt


class LoginTestCase(APITestCase):
    def setUp(self):
        self.url = reverse('login')
        self.url2 = reverse('logout')
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

    def test_logout_success(self):
        response = self.client.post(self.url, data=self.data1, format='json')
        token = response.data['token']
        header = {"HTTP_TOKEN": token}
        response = self.client.post(self.url2, **header)
        self.assertEqual(status.HTTP_202_ACCEPTED, response.status_code)
        self.assertEqual('logout_complete', response.data['code'])

    def test_logout_token_expire_error(self):
        header = {"HTTP_TOKEN": ''}
        response = self.client.post(self.url2, **header)
        self.assertEqual(status.HTTP_403_FORBIDDEN, response.status_code)
        self.assertEqual('token_expire', response.data['detail'])
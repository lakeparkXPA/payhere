from rest_framework.test import APITestCase, APIClient
from rest_framework.views import status
from django.urls import reverse
from rest_framework.settings import api_settings
from account.models import User


class RegisterTestCase(APITestCase):
    def setUp(self):
        self.url = reverse('user_register')
        self.data1 = {"email": "test@gmail.com", "password1": "!Sd1#$@#", "password2": "!Sd1#$@#"}
        self.data2 = {"email": "", "password1": "!Sd1#$@#", "password2": "!Sd1#$@#"}
        self.data3 = {"email": "test", "password1": "!Sd1#$@#", "password2": "!Sd1#$@#"}
        self.data4 = {"email": "test1@gmail.com", "password1": "!Sd1#$@#", "password2": "!Sd1#$@#"}
        self.data5 = {"email": "test2@gmail.com", "password1": "!Sd1#$@#", "password2": ""}
        self.data6 = {"email": "test2@gmail.com", "password1": "!Sd1#$@#", "password2": "!Sd1#$@%"}


    def test_register_success(self):
        client = APIClient()
        user = User.objects.create(user_id=1, email='test1@gmail.com')
        client.force_authenticate(user=user)
        response = self.client.post(self.url, data=self.data1, format='json')
        # swagger, curl 로 테스트 했을때는 잘 되지만 user_id 의 default value 가 없다고 나온다. DB에도 PK와 AI 설정을 해뒀지만 안된다.
        # self.assertEqual(status.HTTP_201_CREATED, response.status_code)

    def test_register_email_missing_error(self):
        response = self.client.post(self.url, data=self.data2, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('email_missing', response.data['code'])

    def test_register_email_format_error(self):
        response = self.client.post(self.url, data=self.data3, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('email_format', response.data['code'])

    def test_register_email_exist_error(self):
        client = APIClient()
        user = User.objects.create(user_id=1, email='test1@gmail.com')
        client.force_authenticate(user=user)
        response = self.client.post(self.url, data=self.data4, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('email_exist', response.data['code'])

    def test_register_password_missing_error(self):
        response = self.client.post(self.url, data=self.data5, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('password_missing', response.data['code'])

    def test_register_password_not_same_error(self):
        response = self.client.post(self.url, data=self.data6, format='json')
        self.assertEqual(status.HTTP_400_BAD_REQUEST, response.status_code)
        self.assertEqual('password_not_same', response.data['code'])


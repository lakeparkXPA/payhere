import jwt

from rest_framework import permissions
from rest_framework import exceptions

from payhere.settings import ALGORITHM, SECRET_KEY
from account.models import User


class UserAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):
        token = request.META.get('HTTP_TOKEN')
        if token is None:
            return False
        else:
            try:
                decoded_token = jwt.decode(token, SECRET_KEY, ALGORITHM)
            except:
                raise exceptions.AuthenticationFailed('token_expire')
            refresh_token = User.objects.get(user_id=decoded_token['id']).refresh_token
            if not refresh_token:
                raise exceptions.AuthenticationFailed('token_expire')
            if decoded_token['auth'] == 'user':
                return True
            else:
                return False

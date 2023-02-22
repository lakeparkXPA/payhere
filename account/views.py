from django.core.validators import validate_email

from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_201_CREATED, HTTP_200_OK, HTTP_202_ACCEPTED
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from account.models import User, Abook

from payhere import error_collection
from tools import make_token

import datetime
import bcrypt


@swagger_auto_schema(
    operation_description='Register account.',
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(
                type=openapi.TYPE_STRING,
                description='Email'),
            'password1': openapi.Schema(
                type=openapi.TYPE_STRING,
                description='Password1'),
            'password2': openapi.Schema(
                type=openapi.TYPE_STRING,
                description='Password2'),
        },
        required=['email', 'password1', 'password2'],
    ),
    responses={
        HTTP_201_CREATED: '\n\n> **회원가입, 토큰 반환**\n\n```\n{\n\n\t"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoicGF0aWVudCIsImlkIjoxOSwiZXhwIjoxNjMzOTY4MTYxfQ.UqAuOEklo8cxTgJtd8nPJSlFgmcZB5Dvd27YGemrgb0",\n\t"refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoicGF0aWVudCIsImlkIjoxOSwiZXhwIjoxNjMzOTY4MTYxfQ.UqAuOEklo8cxTgJtd8nPJSlFgmcZB5Dvd27YGemrgb0"\n\n}\n\n```',
        HTTP_400_BAD_REQUEST: error_collection.RAISE_400_EMAIL_MISSING.as_md() +
                              error_collection.RAISE_400_EMAIL_FORMAT_INVALID.as_md() +
                              error_collection.RAISE_400_EMAIL_EXIST.as_md() +
                              error_collection.RAISE_400_PASSWORD_MISSING.as_md() +
                              error_collection.RAISE_400_PASSWORD_NOT_SAME.as_md(),
    },
)
@api_view(['POST'])
@permission_classes((permissions.AllowAny,))
def register(request):
    email = request.data['email']
    password1 = request.data['password1']
    password2 = request.data['password2']

    try:
        if not email:
            raise ValueError('email_missing')
        try:
            validate_email(email)
        except:
            raise ValueError('email_format')
        else:
            try:
                pass
                id_cnt = User.objects.filter(email=email)

                if len(id_cnt) != 0:
                    raise ValueError('email_exist')
            except User.DoesNotExist:
                pass
        if not password1 or not password2:
            raise ValueError('password_missing')
        if password2 != password1:
            raise ValueError('password_not_same')

        user = User()
        user.email = email

        user.password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user.register_date = datetime.datetime.utcnow()

        token = {'token': make_token(user.pk), 'refresh_token': make_token(user.pk, auth='refresh', hours=6)}

        user.refresh_token = token['refresh_token'].decode()
        user.save()

        return Response(token, status=HTTP_201_CREATED)
    except Exception as e:
        return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)



@swagger_auto_schema(
    operation_description='Return an auth-token for the user account.',
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(
                type=openapi.TYPE_STRING,
                description='Email'),
            'password': openapi.Schema(
                type=openapi.TYPE_STRING,
                description='Password'),
        },
        required=['email', 'password'],
    ),
    responses={
        HTTP_202_ACCEPTED: '\n\n> **로그인, 토큰 반환**\n\n```\n{\n\n\t"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoicGF0aWVudCIsImlkIjoxOSwiZXhwIjoxNjMzOTY4MTYxfQ.UqAuOEklo8cxTgJtd8nPJSlFgmcZB5Dvd27YGemrgb0",\n\t"refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoicGF0aWVudCIsImlkIjoxOSwiZXhwIjoxNjMzOTY4MTYxfQ.UqAuOEklo8cxTgJtd8nPJSlFgmcZB5Dvd27YGemrgb0"\n\n}\n\n```',
        HTTP_400_BAD_REQUEST: error_collection.RAISE_400_EMAIL_FORMAT_INVALID.as_md() +
                              error_collection.RAISE_400_WRONG_PASSWORD.as_md() +
                              error_collection.RAISE_400_WRONG_EMAIL.as_md(),
    },
)
@api_view(['POST'])
@permission_classes((permissions.AllowAny,))
def login(request):
    email = request.data['email']
    password = request.data['password']

    try:
        try:
            validate_email(email)
        except:
            raise ValueError('email_format')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise ValueError('wrong_email')
        else:

            db_pass = user.password
            if not bcrypt.checkpw(password.encode('utf-8'), db_pass.encode('utf-8')):
                raise ValueError('wrong_password')
            else:
                token = {'token': make_token(user.pk), 'refresh_token': make_token(user.pk, auth='refresh', hours=6)}

                user.refresh_token = token['refresh_token'].decode()
                user.save()

                return Response(token, status=HTTP_202_ACCEPTED)

    except Exception as e:
        return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)

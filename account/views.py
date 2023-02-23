from django.core.validators import validate_email

from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions, authentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_201_CREATED, HTTP_200_OK, HTTP_202_ACCEPTED, \
    HTTP_401_UNAUTHORIZED
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from account.models import User, Abook
from account.serializers import AbookGet
from payhere.permissions import UserAuthenticated
from payhere.settings import ALGORITHM, SECRET_KEY

from payhere import error_collection
from tools import make_token, get_id

from pytz import timezone
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
        HTTP_201_CREATED: '\n\n> **회원가입, 토큰 반환**\n\n```\n{\n\n\t"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoicGF0aWVudCIsImlkIjoxOSwiZXhwIjoxNjMzOTY4MTYxfQ.UqAuOEklo8cxTgJtd8nPJSlFgmcZB5Dvd27YGemrgb0"\n\n}\n\n```',
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

        user.register_date = datetime.datetime.now(timezone('Asia/Seoul'))

        token = {'token': make_token(user.pk)}

        user.refresh_token = make_token(user.pk, auth='refresh', hours=6)
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
        HTTP_202_ACCEPTED: '\n\n> **로그인, 토큰 반환**\n\n```\n{\n\n\t"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoicGF0aWVudCIsImlkIjoxOSwiZXhwIjoxNjMzOTY4MTYxfQ.UqAuOEklo8cxTgJtd8nPJSlFgmcZB5Dvd27YGemrgb0"\n\n}\n\n```',
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
                token = {'token': make_token(user.pk)}

                user.refresh_token = make_token(user.pk, auth='refresh', hours=6)
                user.save()

                return Response(token, status=HTTP_202_ACCEPTED)

    except Exception as e:
        return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    operation_description='User logout. Expire refresh token.',
    method='post',
    responses={
        HTTP_202_ACCEPTED: '\n\n> **로그아웃, 리프레시 토큰 제거**\n\n```\n{\n\n\t"message": "logout_complete"\n\n}\n\n```',
        HTTP_401_UNAUTHORIZED: error_collection.RAISE_401_TOKEN_EXPIRE.as_md()
    },
)
@api_view(['POST'])
@permission_classes((UserAuthenticated,))
def logout(request):
    u_id = get_id(request)
    user = User.objects.get(user_id=u_id)
    user.refresh_token = None
    user.save()

    return Response({"code": "logout_complete"}, status=HTTP_202_ACCEPTED)


class Book(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [UserAuthenticated]

    @swagger_auto_schema(
        operation_description='Get abook list data.',
        responses={
            HTTP_200_OK: '\n\n> **기록 목록 반환 (반환 예 하단 참고)**\n\n```\n[\n\t{\n\t\t"abook_id": 1,\n\t\t"abook_time": "2023-01-01 10:08:00",\n\t\t"amount": 120000\n\t},\n\t{\n\t\t"abook_id": 1,\n\t\t"abook_time": "2023-01-01 10:08:00",\n\t\t"amount": 120000\n\t},\n...\n```',
            HTTP_401_UNAUTHORIZED: error_collection.RAISE_401_TOKEN_EXPIRE.as_md(),
        },
    )
    def get(self, request):
        u_id = get_id(request)

        book = Abook.objects.filter(user=u_id)
        book_get = AbookGet(book, many=True).data

        return Response(book_get, status=HTTP_200_OK)

    @swagger_auto_schema(
        operation_description='Save fixed data.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'amount': openapi.Schema(
                    type=openapi.TYPE_NUMBER,
                    description='Amount of money spent'
                ),
                'memo': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Memo on spending amount'
                ),
            },
            required=['amount'],
        ),
        responses={
            HTTP_201_CREATED: 'Abook saved.',
            HTTP_401_UNAUTHORIZED: error_collection.RAISE_401_TOKEN_EXPIRE.as_md(),
            HTTP_400_BAD_REQUEST: error_collection.RAISE_400_NO_AMOUNT.as_md() +
                                  error_collection.RAISE_400_AMOUNT_NUMERIC.as_md()
        },
    )
    def post(self, request):
        u_id = get_id(request)

        try:
            amount = request.data['amount']
        except:
            return Response({"code": "no_amount"}, status=HTTP_400_BAD_REQUEST)
        if not amount:
            return Response({"code": "no_amount"}, status=HTTP_400_BAD_REQUEST)
        if type(amount) != int:
            return Response({"code": "amount_numeric"}, status=HTTP_400_BAD_REQUEST)
        user = User.objects.get(user_id=u_id)
        book = Abook(user=user)
        book.abook_time = datetime.datetime.now(timezone('Asia/Seoul'))
        book.amount = amount
        try:
            memo = request.data['memo']
            book.memo = memo
        except:
            pass
        book.save()

        return Response({"code": "book_saved"}, status=HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_description='Save fixed data.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'abook_id': openapi.Schema(
                    type=openapi.TYPE_NUMBER,
                    description='Abook ID'
                ),
                'amount': openapi.Schema(
                    type=openapi.TYPE_NUMBER,
                    description='Amount of money spent'
                ),
                'memo': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Memo on spending amount'
                ),
            },
            required=['abook_id'],
        ),
        responses={
            HTTP_200_OK: 'Abook updated.',
            HTTP_401_UNAUTHORIZED: error_collection.RAISE_401_TOKEN_EXPIRE.as_md(),
            HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                                  error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
        },
    )
    def put(self, request):
        try:
            abook_id = request.data['abook_id']
        except:
            return Response({"code": "no_abook_id"}, status=HTTP_400_BAD_REQUEST)
        try:
            book = Abook.objects.get(abook_id=abook_id)
        except:
            return Response({"code": "wrong_abook"}, status=HTTP_400_BAD_REQUEST)
        try:
            amount = request.data['amount']
            if amount:
                book.amount = amount

        except:
            pass
        try:
            memo = request.data['memo']
            book.memo = memo
        except:
            pass
        book.save()

        return Response({"code": "abook_updated"}, status=HTTP_200_OK)

    @swagger_auto_schema(
        operation_description='Save fixed data.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'abook_id': openapi.Schema(
                    type=openapi.TYPE_NUMBER,
                    description='Abook ID'
                ),
            },
            required=['abook_id'],
        ),
        responses={
            HTTP_201_CREATED: 'Abook deleted.',
            HTTP_401_UNAUTHORIZED: error_collection.RAISE_401_TOKEN_EXPIRE.as_md(),
            HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                                  error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
        },
    )
    def delete(self, request):
        try:
            abook_id = request.data['abook_id']
        except:
            return Response({"code": "no_abook_id"}, status=HTTP_400_BAD_REQUEST)
        try:
            book = Abook.objects.get(abook_id=abook_id)
            book.delete()
        except:
            return Response({"code": "wrong_abook"}, status=HTTP_400_BAD_REQUEST)

        return Response({"code": "abook_deleted"}, status=HTTP_200_OK)

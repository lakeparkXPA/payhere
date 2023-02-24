from django.core.validators import validate_email
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie

from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions, authentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_201_CREATED, HTTP_200_OK, HTTP_202_ACCEPTED, \
    HTTP_403_FORBIDDEN

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from account.models import User, Abook
from account.serializers import AbookGet, AbookGetDetail, AbookShareDetail

from payhere.permissions import UserAuthenticated
from payhere.settings import ALGORITHM, SECRET_KEY
from payhere import error_collection

from tools import make_token, get_id


from pytz import timezone
import datetime
import bcrypt
import pyshorteners
import jwt


@method_decorator(ensure_csrf_cookie, name='dispatch')
class Register(APIView):
    authentication_classes = []
    permission_classes = []

    @swagger_auto_schema(
        operation_description='Register account.',
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
    def post(self, request):
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
            user.save()

            response = Response(status=HTTP_201_CREATED)
            response.data = {'token': make_token(user.pk)}
            response.set_cookie(key="refreshtoken", value=make_token(user.pk, auth='refresh', hours=6), httponly=True)

            return response
        except Exception as e:
            return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)


@method_decorator(ensure_csrf_cookie, name='dispatch')
class Login(APIView):
    authentication_classes = []
    permission_classes = []

    @swagger_auto_schema(
        operation_description='Return an auth-token for the user account.',
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
    def post(self, request):
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
                    user.save()
                    response = Response(status=HTTP_202_ACCEPTED)
                    response.data = {'token': make_token(user.pk)}
                    response.set_cookie(key="refreshtoken", value=make_token(user.pk, auth='refresh', hours=24),
                                        httponly=True)

                    return response

        except Exception as e:
            return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name='dispatch')
class Logout(APIView):
    authentication_classes = []
    permission_classes = []

    @swagger_auto_schema(
        operation_description='User logout. Expire refresh token.',
        responses={
            HTTP_202_ACCEPTED: '\n\n> **로그아웃, 리프레시 토큰 제거**\n\n```\n{\n\n\t"code": "logout_complete"\n\n}\n\n```',
            HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md()
        },
    )
    def post(self, request):
        response = Response({"code": "logout_complete"}, status=HTTP_202_ACCEPTED)
        response.delete_cookie('refreshtoken')
        return response


@method_decorator(csrf_protect, name='dispatch')
class TokenRefresh(APIView):
    authentication_classes = []
    permission_classes = []

    @swagger_auto_schema(
        operation_description='Refresh an auth-token.',
        responses={
            HTTP_200_OK: '\n\n> **신규 토큰 반환, 토큰 시간 남음, 리프레시 토큰 갱신**\n\n'
                         '```\n{\n\n\t"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoicGF0aWVudCIsImlkIjoxOSwiZXhwIjoxNjMzOTY4MTYxfQ.UqAuOEklo8cxTgJtd8nPJSlFgmcZB5Dvd27YGemrgb0"\n\n}```'
                         '\n\nOr\n\n```\n{\n\n\t"code": "token_remain"\n\n}```'
                         '\n\nOr\n\n```\n{\n\n\t"code": "refresh_token_refreshed"\n\n}```',
            HTTP_403_FORBIDDEN: error_collection.RAISE_403_REFRESH_TOKEN_EXPIRE.as_md(),
        },
    )
    def post(self, request):
        token = request.META.get('HTTP_TOKEN')
        refresh_token = request.COOKIES.get('refreshtoken')

        try:
            if not refresh_token:
                raise ValueError('no_refresh_token')

            if not token:
                raise ValueError('no_token')

            try:
                refresh_decoded = jwt.decode(refresh_token, SECRET_KEY, ALGORITHM)
                decoded_token = jwt.decode(token, SECRET_KEY, ALGORITHM)
                u_id = decoded_token['id']

                try:
                    access_decoded = jwt.decode(token, SECRET_KEY, ALGORITHM)

                    return Response({"code": "token_remain"}, HTTP_200_OK)
                except:
                    token = {'token': make_token(u_id)}
                    return Response(token, HTTP_200_OK)
            except:
                raise ValueError('token_expire')
        except Exception as e:
            return Response({'code': str(e)}, status=HTTP_403_FORBIDDEN)


class Book(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [UserAuthenticated]

    @swagger_auto_schema(
        operation_description='Get abook list data.',
        responses={
            HTTP_200_OK: '\n\n> **기록 목록 반환 (반환 예 하단 참고)**\n\n```\n[\n\t{\n\t\t"abook_id": 1,\n\t\t"abook_time": "2023-01-01 10:08:00",\n\t\t"amount": 120000\n\t},\n\t{\n\t\t"abook_id": 1,\n\t\t"abook_time": "2023-01-01 10:08:00",\n\t\t"amount": 120000\n\t},\n...\n```',
            HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md(),
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
            HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md(),
            HTTP_400_BAD_REQUEST: error_collection.RAISE_400_NO_AMOUNT.as_md() +
                                  error_collection.RAISE_400_AMOUNT_NUMERIC.as_md()
        },
    )
    def post(self, request):
        u_id = get_id(request)
        try:
            try:
                amount = request.data['amount']
            except:
                raise ValueError('no_amount')
            if not amount:
                raise ValueError('no_amount')
            if type(amount) != int:
                raise ValueError('no_amount')
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
        except Exception as e:
            return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)

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
            HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md(),
            HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                                  error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
        },
    )
    def put(self, request):
        try:
            try:
                abook_id = request.data['abook_id']
            except:
                raise ValueError('no_amount')
            try:
                book = Abook.objects.get(abook_id=abook_id)
            except:
                raise ValueError('no_amount')
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
        except Exception as e:
            return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)

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
            HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md(),
            HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                                  error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
        },
    )
    def delete(self, request):
        try:
            try:
                abook_id = request.data['abook_id']
            except:
                raise ValueError('no_amount')
            try:
                book = Abook.objects.get(abook_id=abook_id)
                book.delete()
            except:
                raise ValueError('no_amount')

            return Response({"code": "abook_deleted"}, status=HTTP_200_OK)
        except Exception as e:
            return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    operation_description='Get details of account book.',
    method='get',
    manual_parameters=[
        openapi.Parameter(
            'aid',
            openapi.IN_QUERY,
            type=openapi.TYPE_STRING,
            description='Abook ID'
        ),
    ],
    responses={
        HTTP_200_OK: '\n\n> **가계부 세부 내역 (반환 예 하단 참고)**\n\n```\n{\n\t"abook_id": 7,\n\t"amount": 10000,\n\t"memo": "test memo"\n}\n\n```',
        HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md(),
        HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                              error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
    },
)
@api_view(['GET'])
@permission_classes((UserAuthenticated,))
def abook_detail(request):
    a_id = request.GET.get('aid')
    try:
        if not a_id:
            raise ValueError('no_amount')
        try:
            book = Abook.objects.get(abook_id=int(a_id))
        except:
            raise ValueError('no_amount')

        book_get = AbookGetDetail(book).data

        return Response(book_get, status=HTTP_200_OK)
    except Exception as e:
        return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    operation_description='Duplicate given account book detail',
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'abook_id': openapi.Schema(
                type=openapi.TYPE_NUMBER,
                description='Account book id'
            ),

        },
        required=['abook_id'],
    ),
    responses={
        HTTP_202_ACCEPTED: '\n\n> **받은 가계부 세부내역 복제**\n\n```\n{\n\n\t"message": "detail_duplicated"\n\n}\n\n```',
        HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md(),
        HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                              error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
    },
)
@api_view(['POST'])
@permission_classes((UserAuthenticated,))
def abook_detail_duplicate(request):
    try:
        try:
            a_id = request.data['abook_id']
        except:
            raise ValueError('no_amount')
        try:
            book = Abook.objects.get(abook_id=int(a_id))
        except:
            raise ValueError('no_amount')

        user = User.objects.get(user_id=book.user.user_id)
        book_dup = Abook(user=user)
        book_dup.abook_time = datetime.datetime.now(timezone('Asia/Seoul'))
        book_dup.amount = book.amount
        book_dup.memo = book.memo
        book_dup.save()

        return Response({"code": "detail_duplicated"}, status=HTTP_200_OK)
    except Exception as e:
        return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    operation_description='Share details of account book.',
    method='get',
    manual_parameters=[
        openapi.Parameter(
            'aid',
            openapi.IN_QUERY,
            type=openapi.TYPE_STRING,
            description='Abook ID'
        ),
    ],
    responses={
        HTTP_200_OK: '\n\n> **가계부 세부 내역 (반환 예 하단 참고)**\n\n```\n{\n\t"abook_id": 7,\n\t"amount": 10000,\n\t"memo": "test memo"\n}\n\n```',
        HTTP_403_FORBIDDEN: error_collection.RAISE_403_TOKEN_EXPIRE.as_md(),
        HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                              error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
    },
)
@api_view(['GET'])
@permission_classes((UserAuthenticated,))
def abook_share(request):
    a_id = request.GET.get('aid')
    try:
        if not a_id:
            raise ValueError('no_amount')
        try:
            book = Abook.objects.get(abook_id=int(a_id))
        except:
            raise ValueError('no_amount')

        url = 'http://127.0.0.1:8000/account/dshare?aid=' + a_id
        shortener = pyshorteners.Shortener(timeout=10)
        shortened_url = shortener.tinyurl.short(url)

        return Response({"url": shortened_url}, status=HTTP_200_OK)
    except Exception as e:
        return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    operation_description='Share details of account book.',
    method='get',
    manual_parameters=[
        openapi.Parameter(
            'aid',
            openapi.IN_QUERY,
            type=openapi.TYPE_STRING,
            description='Abook ID'
        ),
    ],
    responses={
        HTTP_200_OK: '\n\n> **공유 가계부 세부 내역 (반환 예 하단 참고)**\n\n```\n{\n\t"amount": 10000,\n\t"memo": "test memo"\n}\n\n```',
        HTTP_400_BAD_REQUEST: error_collection.RAISE_400_WRONG_ABOOK.as_md() +
                              error_collection.RAISE_400_NO_ABOOK_ID.as_md(),
    },
)
@api_view(['GET'])
@permission_classes((permissions.AllowAny,))
def abook_detail_share(request):
    a_id = request.GET.get('aid')
    try:
        if not a_id:
            raise ValueError('no_amount')
        try:
            book = Abook.objects.get(abook_id=int(a_id))
        except:
            raise ValueError('no_amount')

        book_get = AbookShareDetail(book).data

        return Response(book_get, status=HTTP_200_OK)
    except Exception as e:
        return Response({"code": str(e)}, status=HTTP_400_BAD_REQUEST)

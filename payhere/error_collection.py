from rest_framework import status


class ErrorCollection(object):

    def __init__(self, code, status, message):
        self.code = code
        self.status = status
        self.message = message


    def as_md(self):
        return '\n\n> **%s**\n\n```\n{\n\n\t"code": "%s"\n\n}\n\n```' % \
               (self.message, self.code) # \n\n\t"message": "%s"     self.message



RAISE_400_EMAIL_MISSING = ErrorCollection(
    code='email_missing',
    status=status.HTTP_400_BAD_REQUEST,
    message='이메일이 존재하지 않습니다.'
)
RAISE_400_EMAIL_FORMAT_INVALID = ErrorCollection(
    code='email_format',
    status=status.HTTP_400_BAD_REQUEST,
    message='이메일 형식이 아닙니다.'
)
RAISE_400_EMAIL_EXIST = ErrorCollection(
    code='email_exist',
    status=status.HTTP_400_BAD_REQUEST,
    message='이메일이 존재합니다.'
)
RAISE_400_WRONG_PASSWORD = ErrorCollection(
    code='wrong_password',
    status=status.HTTP_400_BAD_REQUEST,
    message='비밀번호가 틀렸습니다.'
)
RAISE_400_PASSWORD_MISSING = ErrorCollection(
    code='password_missing',
    status=status.HTTP_400_BAD_REQUEST,
    message='비밀번호기 존재하지 않습니.'
)
RAISE_400_PASSWORD_NOT_SAME = ErrorCollection(
    code='password_not_same',
    status=status.HTTP_400_BAD_REQUEST,
    message='두 비밀번호가 다릅니다.'
)

RAISE_400_WRONG_EMAIL = ErrorCollection(
    code='wrong_email',
    status=status.HTTP_400_BAD_REQUEST,
    message='이메일이 틀렸습니다.'
)
RAISE_403_TOKEN_EXPIRE = ErrorCollection(
    code='token_expire',
    status=status.HTTP_403_FORBIDDEN,
    message='토큰이 만료됐습니다.'
)
RAISE_403_REFRESH_TOKEN_EXPIRE = ErrorCollection(
    code='refresh_token_expire',
    status=status.HTTP_403_FORBIDDEN,
    message='토큰이 만료됐습니다.'
)
RAISE_400_NO_ABOOK = ErrorCollection(
    code='no_abook',
    status=status.HTTP_400_BAD_REQUEST,
    message='기록이 없습니다.'
)
RAISE_400_NO_AMOUNT = ErrorCollection(
    code='no_amount',
    status=status.HTTP_400_BAD_REQUEST,
    message='금액이 없습니다.'
)
RAISE_400_AMOUNT_NUMERIC = ErrorCollection(
    code='amount_numeric',
    status=status.HTTP_400_BAD_REQUEST,
    message='금액은 숫자형이어야 합니다.'
)
RAISE_400_WRONG_ABOOK = ErrorCollection(
    code='wrong_abook',
    status=status.HTTP_400_BAD_REQUEST,
    message='abook id가 올바르지 않습니다.'
)
RAISE_400_NO_ABOOK_ID = ErrorCollection(
    code='no_abook_id',
    status=status.HTTP_400_BAD_REQUEST,
    message='abook id가 없습니다.'
)
RAISE_400_TIME_EXPIRE = ErrorCollection(
    code='time_expire',
    status=status.HTTP_400_BAD_REQUEST,
    message='abook id가 없습니다.'
)
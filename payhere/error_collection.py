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
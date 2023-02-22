import datetime
import jwt

from payhere.settings import ALGORITHM, SECRET_KEY


def make_token(token_id, auth='user', hours=1):
    payload = {}
    payload['auth'] = auth
    payload['id'] = token_id
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(hours=hours)

    return jwt.encode(payload, SECRET_KEY, ALGORITHM)


def get_id(request):
    token = request.META.get('HTTP_TOKEN')
    decoded_token = jwt.decode(token, SECRET_KEY, ALGORITHM)
    return decoded_token['id']
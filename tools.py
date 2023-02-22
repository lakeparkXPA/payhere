import datetime
import jwt

from payhere.settings import ALGORITHM, SECRET_KEY


def make_token(token_id, auth='patient', hours=1):
    payload = {}
    payload['auth'] = auth
    payload['id'] = token_id
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(hours=hours)

    return jwt.encode(payload, SECRET_KEY, ALGORITHM)
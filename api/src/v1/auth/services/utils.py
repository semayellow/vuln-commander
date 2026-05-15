import bcrypt
import jwt
from jwt import PyJWTError
from pydantic import ValidationError

from api.src.core.utils import Config, exception, log

from shared.schemas.auth import TokenSchema
from api.src.v1.user.models.user_model import User
from api.src.v1.connector.models.connector_model import Connector


async def is_valid_password(new_password: str, saved_password: bytes) -> bool:
    return bcrypt.checkpw(encode_password(new_password), saved_password)


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed_password = encode_password(password)
    return bcrypt.hashpw(hashed_password, salt)


def encode_password(password: str) -> bytes:
    try:
        return password.encode()
    except UnicodeEncodeError:
        raise exception.auth.invalid_password_encoding()


async def encode_access_token(entity: User | Connector, created_at: float, expire: float) -> str:
    return jwt.encode(
        payload={
            'sub': str(entity.id),
            'expire': expire,
            'iat': created_at,
            'scope': 'user' if isinstance(entity, User) else 'connector'
        },
        key=Config.PRIVATE_KEY,
        algorithm=Config.ENCRYPTION_ALGORYTHM
    )


async def decode_access_token(token: str) -> TokenSchema:
    try:
        token_payload = jwt.decode(
            token,
            Config.PUBLIC_KEY,
            Config.ENCRYPTION_ALGORYTHM
        )
        token = TokenSchema(**token_payload)
        return token
    except (PyJWTError, ValidationError) as error:
        log.error(error)
        raise exception.token.invalid_access_token()

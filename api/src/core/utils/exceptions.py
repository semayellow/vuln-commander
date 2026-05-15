from fastapi import HTTPException, status
from typing import Self


class GenericException(HTTPException):
    def __init__(self, status_code: int, details: str) -> None:
        details = f'[vuln-commander api exception] {details}.'
        super().__init__(status_code, details)

    @classmethod
    def inactive_entity(cls, entity_type: str) -> Self:
        return cls(
            status.HTTP_403_FORBIDDEN,
            f'{entity_type} is inactive'
        )

    @classmethod
    def entity_not_found(cls, entity_type: str) -> Self:
        return cls(
            status.HTTP_404_NOT_FOUND,
            f'requested {entity_type} is not found'
        )

    @classmethod
    def duplicate_name(cls, entity_type: str) -> Self:
        return cls(
            status.HTTP_400_BAD_REQUEST,
            f'this {entity_type} is already exists'
        )

    @classmethod
    def empty_request_payload(cls, request_part: str) -> Self:
        return cls(
            status.HTTP_400_BAD_REQUEST,
            f'the request {request_part} must do not be empty'
        )

    @classmethod
    def internal_server_error(cls) -> Self:
        return cls(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            'internal server error'
        )


class AuthException(HTTPException):
    def __init__(self, status_code: int, details: str) -> None:
        details = f'[vuln-commander api exception] {details}.'
        super().__init__(status_code, details)

    @classmethod
    def bad_credentials(cls) -> Self:
        return cls(
            status.HTTP_401_UNAUTHORIZED,
            'invalid username or password'
        )

    @classmethod
    def invalid_password_encoding(cls) -> Self:
        return cls(
            status.HTTP_400_BAD_REQUEST,
            'invalid password, please use only utf-8 characters'
        )

    @classmethod
    def invalid_capabilities(cls) -> Self:
        return cls(
            status.HTTP_403_FORBIDDEN,
            'you do not have sufficient rights to access this resource'
        )


class TokenException(HTTPException):
    def __init__(self, status_code: int, details: str) -> None:
        details = f'[vuln-commander api exception] {details}.'
        super().__init__(status_code, details)

    @classmethod
    def invalid_access_token(cls) -> Self:
        return cls(
            status.HTTP_401_UNAUTHORIZED,
            'access token is invalid'
        )

    @classmethod
    def access_token_expired(cls) -> Self:
        return cls(
            status.HTTP_401_UNAUTHORIZED,
            'access token is expired'
        )

    @classmethod
    def invalid_refresh_token(cls) -> Self:
        return cls(
            status.HTTP_400_BAD_REQUEST,
            'refresh token is invalid'
        )

    @classmethod
    def refresh_token_not_found(cls) -> Self:
        return cls(
            status.HTTP_404_NOT_FOUND,
            'there are no active refresh tokens'
        )

    @classmethod
    def refresh_token_expired(cls) -> Self:
        return cls(
            status.HTTP_401_UNAUTHORIZED,
            'refresh token is expired'
        )


class Exceptions:
    generic = GenericException
    auth = AuthException
    token = TokenException

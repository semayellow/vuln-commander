import os
from dotenv import load_dotenv

load_dotenv()


def load_rsa_key(key_type: str) -> bytes:
    key_path = f'/vuln-commander/api/certs/jwt-{key_type}.pem'

    with open(key_path, 'rb') as key:
        return key.read()


class Config:
    # Base settings
    DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    LOGS_FILEPATH: str = 'api/logs/error.log'

    # PSQL settings
    DB_PORT = os.environ.get('POSTGRESQL_PORT_NUMBER')
    DB_USER = os.environ.get('POSTGRESQL_USERNAME')
    DB_PASS = os.environ.get('POSTGRESQL_PASSWORD')
    DB_NAME = os.environ.get('POSTGRESQL_DATABASE')
    POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')
    PSQL_CONNECTION: str = f'postgresql+asyncpg://{DB_USER}:{DB_PASS}@{POSTGRESQL_HOST}:{DB_PORT}/{DB_NAME}'

    # External UI links (landing page)
    GRAFANA_URL: str = os.environ.get('GRAFANA_URL', 'http://localhost:3000')
    GRAYLOG_URL: str = os.environ.get('GRAYLOG_URL', 'http://localhost:9000')
    PGADMIN_URL: str = os.environ.get('PGADMIN_URL', 'http://localhost:8080')

    # Web UI auth cookies
    ACCESS_TOKEN_COOKIE: str = 'vc_access_token'
    REFRESH_TOKEN_COOKIE: str = 'vc_refresh_token'
    COOKIE_SECURE: bool = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'

    # PGAdmin settings
    PRIVATE_KEY: bytes = load_rsa_key('private')
    PUBLIC_KEY: bytes = load_rsa_key('public')
    ENCRYPTION_ALGORYTHM: str = 'RS256'

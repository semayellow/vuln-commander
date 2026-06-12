import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    CONNECTOR_ID: str = os.environ.get('CONNECTOR_IAC_UUID')
    CONNECTOR_PASSWORD: str = os.environ.get('CONNECTOR_IAC_PASSWORD')
    CRON_SCHEDULE: str = os.environ.get('CRON_SCHEDULE')
    PARALLEL_TASKS_COUNT: int = int(os.environ.get('PARALLEL_TASKS_COUNT'))
    VULNS_REQUEST_BATCH_SIZE: int = int(os.environ.get('VULNS_REQUEST_BATCH_SIZE'))
    GRAYLOG_UDP_PORT: int = int(os.environ.get('GRAYLOG_UDP_PORT'))

    SCANER_PATH: str = 'iac/scanner/kics'
    QUERIES_PATH: str = 'iac/scanner/queries'
    CONNECTOR_TYPE: str = 'iac'


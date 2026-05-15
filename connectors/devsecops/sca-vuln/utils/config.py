import os

from dotenv import load_dotenv
from shared.schemas.constants import ConnectorType

load_dotenv()


class Config:
    CONNECTOR_ID: str = os.environ.get('CONNECTOR_ID')
    CONNECTOR_PASSWORD: str = os.environ.get('CONNECTOR_PASSWORD')
    CRON_SCHEDULE: str = os.environ.get('CRON_SCHEDULE')
    PARALLEL_TASKS_COUNT: int = int(os.environ.get('PARALLEL_TASKS_COUNT'))
    VULNS_REQUEST_BATCH_SIZE: int = int(os.environ.get('VULNS_REQUEST_BATCH_SIZE'))
    GRAYLOG_UDP_PORT: int = int(os.environ.get('GRAYLOG_UDP_PORT'))

    SCANER_PATH: str = 'sca/trivy/trivy'
    CONNECTOR_TYPE = ConnectorType.sca_vuln

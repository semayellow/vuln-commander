import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    CONNECTOR_ID: str = os.environ.get('CONNECTOR_GITHUB_UUID')
    CONNECTOR_PASSWORD: str = os.environ.get('CONNECTOR_GITHUB_PASSWORD')
    CRON_SCHEDULE: str = os.environ.get('CRON_SCHEDULE')
    GRAYLOG_UDP_PORT: int = int(os.environ.get('GRAYLOG_UDP_PORT'))
    PARALLEL_TASKS_COUNT: int = int(os.environ.get('PARALLEL_TASKS_COUNT'))

    PROJECTS_PATH: str = os.environ.get(
        'PROJECTS_PATH',
        '/vuln-commander/github/projects.txt',
    )

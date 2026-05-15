import os
import sys
import logging

import pygelf
from datetime import datetime, UTC
from loguru import logger


class StdLogger:
    """Implements saving logs to the text file"""

    def __init__(self):
        self.logger = logger

        self.logger.configure(
            handlers=[
                {
                    'sink': sys.stdout,
                    'format': '{extra[datetime]} | {level} | {message}',
                }
            ],
            extra={
                'retention': '1 month',
                'rotation': '1 week'
            },
            patcher=self._patch_timezone
        )

    @staticmethod
    def _patch_timezone(record):
        record['extra']['datetime'] = datetime.now(UTC)

    @staticmethod
    def info(message: str) -> None:
        logger.info(message)

    @staticmethod
    def warning(message: str) -> None:
        logger.warning(message)

    @staticmethod
    def error(message: str) -> None:
        logger.error(message)


class GrayLogLogger:
    def __init__(self, port: int) -> None:
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

        connector = os.environ.get('VC_CONNECTOR_NAME', '').strip() or 'unknown'

        gelf_handler = pygelf.GelfUdpHandler(
            host='graylog',
            port=port,
            compress=True,
            debugging_fields=True,
            static_fields={'_vc_connector': connector},
        )

        self.logger.addHandler(gelf_handler)


std_log = StdLogger()

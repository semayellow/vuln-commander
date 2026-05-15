import time

from typing import Self
from datetime import datetime, UTC

from cron_converter import Cron


class Scheduler:
    def __init__(self, cron_time: str) -> None:
        cron = Cron(cron_time)
        self._scheduler = cron.schedule(datetime.now(UTC))
        self._next_run_at = datetime.now(UTC)

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> datetime:

        while datetime.now(UTC) < self._next_run_at:
            time.sleep(1)

        self._next_run_at = self._scheduler.next()

        return self._next_run_at

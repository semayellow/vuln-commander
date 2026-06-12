import asyncio
import time
from abc import ABC, abstractmethod
from itertools import batched

from sdk.src.scheduler import Scheduler
from sdk.src.base import VulnCommanderSDK
from sdk.src.utils.logger import GrayLogLogger
from shared.schemas.constants import ConnectorType
from shared.schemas.project import ProjectResponseSchema


class BaseScanner(ABC):
    def __init__(self, connector_type: ConnectorType, config) -> None:
        self._config = config
        self._logger = GrayLogLogger()

        self._processed_projects = 0
        self._connector_type = connector_type

    async def run_scan(self) -> None:
        async with VulnCommanderSDK(
            self._config.CONNECTOR_ID,
            self._config.CONNECTOR_PASSWORD,
        ) as sdk:
            projects = await sdk.get_projects(self._connector_type)

            if not projects:
                self._logger.info('Available projects are not found. Skipping current scan...')
                return

            for chunk in batched(projects, self._config.PARALLEL_TASKS_COUNT):
                tasks = [
                    asyncio.create_task(self._scan_project(project, sdk))
                    for project in chunk
                ]
                await asyncio.gather(*tasks)
                self._processed_projects += self._config.PARALLEL_TASKS_COUNT
                self._logger.info(f'Processed {self._processed_projects}/{len(projects)}.')

    def run(self) -> None:
        time.sleep(5)
        for next_run in Scheduler(self._config.CRON_SCHEDULE):
            self._logger.info('Connector started')
            asyncio.run(self.run_scan())
            self._logger.info(f'Successful run. Next run at: {next_run}')

    @abstractmethod
    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        pass

import asyncio
import json
import subprocess
import os
import time
from datetime import datetime, UTC
from concurrent.futures import ThreadPoolExecutor
from itertools import batched

import aiofiles
from aiofiles import tempfile
from git import Repo

from sdk import Scheduler, VulnCommanderSDK
from sdk.src.utils import GrayLogLogger, get_running_loop, std_log
from sdk.src.utils.helpers import generate_vuln_hash

from shared.schemas.constants import VulnSeverity, VulnStatus
from shared.schemas.project import ProjectResponseSchema
from shared.schemas.vuln import VulnSchema

from utils.config import Config
from utils.models import Licenses


class ScaScaner:
    def __init__(self, log: GrayLogLogger) -> None:
        self._processed_projects = 0
        self._log = log.logger

    async def run(self) -> None:
        async with VulnCommanderSDK(Config.CONNECTOR_ID, Config.CONNECTOR_PASSWORD) as sdk:
            projects = await sdk.get_projects(Config.CONNECTOR_TYPE)

            for chunk in batched(projects, Config.PARALLEL_TASKS_COUNT):
                tasks = [asyncio.create_task(self._scan_project(project, sdk)) for project in chunk]
                await asyncio.gather(*tasks)

                self._processed_projects += Config.PARALLEL_TASKS_COUNT
                self._log.info(f'Processed {self._processed_projects}/{len(projects)}.')
                tasks.clear()

    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        log.logger.info(f'Cloning the project: {project.name}')
        async with tempfile.TemporaryDirectory() as temp_dir:
            clone_path, report_path = await self._prepare_paths(project, temp_dir)

            await self._initialize_scanner(clone_path, report_path)
            severity_counters = await self._process_vulns(project, sdk, report_path)

            await sdk.create_or_update_history(
                Config.CONNECTOR_TYPE,
                project.project_id,
                project.last_commit_hash,
                **severity_counters
            )

            subprocess.run(['/bin/rm', report_path])


    async def _initialize_scanner(
        self,
        clone_path: str,
        report_path: str
    ) -> None:

        loop = get_running_loop()
        with ThreadPoolExecutor() as pool:
            await loop.run_in_executor(
                pool, self._execute_scanner, clone_path, report_path
            )

    async def _process_vulns(
        self,
        project: ProjectResponseSchema,
        sdk: VulnCommanderSDK,
        report_path: str
    ) -> dict[str, int] | dict:
        if not os.path.isfile(report_path):
            return {}

        async with aiofiles.open(report_path, 'r') as file:
            report = json.loads(await file.read())

        result = await self._parse_report(report, project)

        if result:
            severity_counters, vulns = result
            if vulns:
                await sdk.process_vulns(vulns, project.vulns)
                return severity_counters
        return {}

    async def _parse_report(
        self,
        report: dict,
        project: ProjectResponseSchema
    ) -> tuple[dict[str, int], dict[str, VulnSchema]] | None:

        if not report.get('Results'):
            return

        vulns = dict()

        for result in Licenses(**report).results:
            if result and (entries := result.licenses):
                for entry in entries:
                    severity = VulnSeverity(entry.severity.lower()) if entry.severity != 'UNKNOWN' else VulnSeverity('info')
                    custom_fields = {
                        'package_name': entry.package_name or 'no info',
                        'license_name': entry.name,
                        'link': entry.link or 'no info',
                    }

                    vuln_hash = await generate_vuln_hash(
                        project_id=str(project.project_id),
                        connector_type=Config.CONNECTOR_TYPE,
                        severity=severity,
                        filepath=entry.filepath,
                        line='no info',
                        custom_fields=custom_fields
                    )

                    vulns.update(
                        {
                            vuln_hash:VulnSchema(
                                project_id=str(project.project_id),
                                last_commit_hash=project.last_commit_hash,
                                created_at=datetime.now(UTC),
                                connector_type=Config.CONNECTOR_TYPE,
                                severity=severity,
                                status=VulnStatus.new,
                                filepath=entry.filepath,
                                line='no info',
                                code_snippet='no info',
                                custom_fields=custom_fields,
                                hash=vuln_hash
                            )
                        }
                    )
        log.logger.info(f'Counters: {Licenses(**report).severity_counters()}')
        log.logger.info(f'Vulns: {vulns}')
        return Licenses(**report).severity_counters(), vulns

    @staticmethod
    async def _prepare_paths(project: ProjectResponseSchema, temp_dir: str) -> tuple[str, str]:
        clone_path = os.path.join(temp_dir, project.name)
        Repo.clone_from(project.clone_url, clone_path)

        scanner_working_directory = os.path.join('sca', 'scaner_working_directory')

        if not os.path.isdir(scanner_working_directory):
            os.mkdir(scanner_working_directory)

        report_path = os.path.join(scanner_working_directory, f'{project.project_id}_report.json')

        return clone_path, report_path


    def _execute_scanner(
        self,
        clone_path: str,
        report_path: str
    ) -> None:
        log.logger.info(f'Installing dependencies')
        dependencies_path = self._install_dependencies(clone_path)

        log.logger.info(f'Executing scanner dependencies')
        subprocess.run(
            [
                Config.SCANER_PATH,
                "repo",
                "--scanners",
                "license",
                "--license-full",
                "--quiet",
                dependencies_path,
                "-s",
                "UNKNOWN,MEDIUM,HIGH,CRITICAL",
                "-f",
                "json",
                "-o",
                report_path
            ]
        )
        log.logger.info(f'Executing scanner success')

    @staticmethod
    def _install_dependencies(clone_path: str) -> str:

        try:
            if os.path.isfile(f'{clone_path}/package.json'):
                log.logger.info(f'JS Project detected, clone path: {clone_path}')

                command = 'ci' if os.path.isfile(f'{clone_path}/package-lock.json') else 'install'

                subprocess.run(
                    f'export NVM_DIR="$HOME/.nvm" '
                    f'&& . "$NVM_DIR/nvm.sh" '
                    f'&& nvm use 22 && npm {command} --ignore-scripts',
                    check=True, shell=True, cwd=clone_path, executable='/bin/bash'
                )
                if os.path.isdir(f'{clone_path}/node_modules'):
                    return f'{clone_path}/node_modules'
            elif os.path.isfile(f'{clone_path}/pyproject.toml'):
                log.logger.info(f'Python project with project.toml detected')
                subprocess.run(['uv', 'venv'], check=True, cwd=clone_path)
                subprocess.run(['uv', 'pip', 'install', '-r', 'pyproject.toml'], check=True, cwd=clone_path)
            elif os.path.isfile(f'{clone_path}/requirements.txt'):
                log.logger.info(f'Python project with requirements.txt detected')
                subprocess.run(['uv', 'venv'], check=True, cwd=clone_path)
                subprocess.run(['uv', 'pip', 'install', '-r', 'requirements.txt'], check=True, cwd=clone_path,)
        except subprocess.CalledProcessError:
            log.logger.info(f'Failed to install dependencies for the project: {os.path.basename(clone_path)}')

        return clone_path



if __name__ == '__main__':
    time.sleep(5)
    log = GrayLogLogger(Config.GRAYLOG_UDP_PORT)
    scaner = ScaScaner(log)
    for next_run in Scheduler(Config.CRON_SCHEDULE):
        log.logger.info('Connector started')
        asyncio.run(scaner.run())
        log.logger.info(f'Successful run. Next run at: {next_run}')

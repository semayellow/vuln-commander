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
from sdk.src.utils import GrayLogLogger, get_running_loop
from sdk.src.utils.helpers import generate_vuln_hash

from shared.schemas.constants import VulnSeverity, VulnStatus
from shared.schemas.project import ProjectResponseSchema
from shared.schemas.vuln import VulnSchema

from utils.config import Config
from utils.models import VulnScan


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

        for result in VulnScan(**report).results:
            if result and (entries := result.vulnerabilities):
                for entry in entries:
                    severity = VulnSeverity(entry.severity.lower()) if entry.severity != 'UNKNOWN' else VulnSeverity('info')
                    cvss_score = self._get_cvss_score(entry.cvss)
                    custom_fields = {
                        'package_manager': result.package_manager,
                        'package_name': entry.package_name,
                        'installed_version': entry.installed_version,
                        'fixed_version': entry.fixed_version or 'no info',
                        'status': entry.status,
                        'recommendation_url': entry.recommendation_url or 'no info',
                        'vuln_title': entry.title,
                        'vuln_description': entry.description,
                        'cvss_score': cvss_score
                    }

                    vuln_hash = await generate_vuln_hash(
                        project_id=str(project.project_id),
                        connector_type=Config.CONNECTOR_TYPE,
                        severity=severity,
                        filepath='no info',
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
                                filepath='no info',
                                line='no info',
                                code_snippet='no info',
                                custom_fields=custom_fields,
                                hash=vuln_hash
                            )
                        }
                    )
        log.logger.info(f'Counters: {VulnScan(**report).severity_counters()}')
        log.logger.info(f'Vulns: {vulns}')
        return VulnScan(**report).severity_counters(), vulns

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
        log.logger.info(f'Converting dependencies')
        self._convert_dependencies(clone_path)

        log.logger.info(f'Executing scanner dependencies')
        subprocess.run(
            [
                Config.SCANER_PATH,
                "repo",
                "--scanners",
                "vuln",
                "--quiet",
                clone_path,
                "-f",
                "json",
                "-o",
                report_path
            ]
        )
        log.logger.info(f'Executing scanner success')

    @staticmethod
    def _convert_dependencies(clone_path: str) -> None:
       try:
            if os.path.isfile(f'{clone_path}/pyproject.toml'):
                subprocess.run(
                    'uv pip compile pyproject.toml > requirements.txt',
                    check=True, cwd=clone_path, shell=True
                )
       except subprocess.CalledProcessError:
           log.logger.info(f'Failed to compile dependencies for the project: {os.path.basename(clone_path)}')
    
    @staticmethod
    def _get_cvss_score(cvss: dict | None) -> str | float:
        if not cvss:
            return 'no info'
        scores = [score for metric, info in cvss.items() if (score:= info.get('V3Score'))]

        if not scores:
            return 'no info'

        return max(scores)


if __name__ == '__main__':
    time.sleep(5)
    log = GrayLogLogger(Config.GRAYLOG_UDP_PORT)
    scaner = ScaScaner(log)
    for next_run in Scheduler(Config.CRON_SCHEDULE):
        log.logger.info('Connector started')
        asyncio.run(scaner.run())
        log.logger.info(f'Successful run. Next run at: {next_run}')

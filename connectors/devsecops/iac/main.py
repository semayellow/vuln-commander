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
from sdk.src.utils.helpers import sanitize, generate_vuln_hash

from shared.schemas.constants import ConnectorType, VulnSeverity, VulnStatus
from shared.schemas.project import ProjectResponseSchema
from shared.schemas.vuln import VulnSchema

from utils.config import Config
from utils.models import Vulns, SeverityCounters


class IacScaner:
    def __init__(self, log: GrayLogLogger) -> None:
        self._processed_projects = 0
        self._log = log.logger

    async def run(self) -> None:
        async with VulnCommanderSDK(Config.CONNECTOR_ID, Config.CONNECTOR_PASSWORD) as sdk:
            projects = await sdk.get_projects(ConnectorType.iac)

            for chunk in batched(projects, Config.PARALLEL_TASKS_COUNT):
                tasks = [asyncio.create_task(self._scan_project(project, sdk)) for project in chunk]
                await asyncio.gather(*tasks)

                self._processed_projects += Config.PARALLEL_TASKS_COUNT
                self._log.info(f'Processed {self._processed_projects}/{len(projects)}.')
                tasks.clear()

    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        log.logger.info(f'Scanning the project: {project.name}')
        async with tempfile.TemporaryDirectory() as temp_dir:
            clone_path, report_path = await self._prepare_paths(project, temp_dir)

            await self._initialize_scanner(clone_path, report_path)
            severity_counters = await self._process_vulns(project, sdk, report_path)

            await sdk.create_or_update_history(
                ConnectorType.iac,
                project.project_id,
                project.last_commit_hash,
                **severity_counters
            )

            subprocess.run(['/bin/rm', '-rf', report_path])


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
    ) -> SeverityCounters | dict:

        async with aiofiles.open(f'{report_path}/results.json', 'r') as file:
            report = json.loads(await file.read())

        severity_counters, vulns = await self._parse_report(report, project)

        if vulns:
            await sdk.process_vulns(vulns, project.vulns)
            return severity_counters

        return {}

    async def _parse_report(
        self,
        report: dict,
        project: ProjectResponseSchema
    ) -> tuple[SeverityCounters, dict[str, VulnSchema]] | None:

        if not report.get('total_counter'):
            return

        vulns = dict()

        for query in Vulns(**report).queries:
            rule_name = query.query_name
            rule_text_id = query.query_id
            recommendation_url = query.query_url
            severity = VulnSeverity(query.severity.lower()) if query.severity != 'TRACE' else VulnSeverity('info')
            platform = query.platform
            cwe_url = f'https://cwe.mitre.org/data/definitions/{query.cwe}.html'
            category = query.category
            description = query.description
            for file in query.files:
                filepath = '/'.join(file.file_name.replace('\\', '/').split('/')[3:])
                line = str(file.line)
                rule_search_key = file.search_key
                actual_value = file.actual_value
                recommended_value = file.expected_value
                code_snippet = 'no info'

                project_id = str(project.project_id)
                last_commit_hash = project.last_commit_hash
                connector_type = ConnectorType.iac
                status = VulnStatus.new

                custom_fields = {
                    'platform': platform,
                    'category': category,
                    'rule_name': rule_name,
                    'description': description,
                    'actual_value': actual_value,
                    'recommended_value': recommended_value,
                    'recommendation_url': recommendation_url,
                    'cwe_url': cwe_url,
                    'rule_text_id': rule_text_id,
                    'rule_search_key': rule_search_key,
                }

                vuln_hash = await generate_vuln_hash(
                    project_id=project_id,
                    connector_type=connector_type,
                    severity=severity,
                    filepath=filepath,
                    line=line,
                    custom_fields=custom_fields
                )

                vulns.update(
                    {
                        vuln_hash:VulnSchema(
                            project_id=project_id,
                            last_commit_hash=last_commit_hash,
                            created_at=datetime.now(UTC),
                            connector_type=connector_type,
                            severity=severity,
                            status=status,
                            filepath=filepath,
                            line=line,
                            code_snippet=code_snippet,
                            custom_fields=custom_fields,
                            hash=vuln_hash
                        )
                    }
                )

        return Vulns(**report).severity_counters.model_dump(), vulns

    @staticmethod
    async def _prepare_paths(project: ProjectResponseSchema, temp_dir: str) -> tuple[str, str]:
        clone_path = os.path.join(temp_dir, project.name)
        Repo.clone_from(project.clone_url, clone_path)

        scanner_working_directory = os.path.join('iac', 'scaner_working_directory')

        if not os.path.isdir(scanner_working_directory):
            os.mkdir(scanner_working_directory)

        report_path = os.path.join(scanner_working_directory, str(project.project_id))

        return clone_path, report_path


    @staticmethod
    def _execute_scanner(
        clone_path: str,
        report_path: str
    ) -> None:

        subprocess.run(
            [
                Config.SCANER_PATH,
                '-s',
                'scan',
                '-p',
                clone_path,
                '-q',
                Config.QUERIES_PATH,
                '--report-formats',
                'json',
                '-o',
                report_path
            ],
            timeout=60 * 30
        )


if __name__ == '__main__':
    time.sleep(5)
    log = GrayLogLogger(Config.GRAYLOG_UDP_PORT)
    scaner = IacScaner(log)
    for next_run in Scheduler(Config.CRON_SCHEDULE):
        log.logger.info('Connector started')
        asyncio.run(scaner.run())
        log.logger.info(f'Successful run. Next run at: {next_run}')

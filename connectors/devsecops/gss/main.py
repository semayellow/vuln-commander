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
from utils.models import Vulns


class GssScaner:
    def __init__(self, log: GrayLogLogger) -> None:
        self._processed_projects = 0
        self._log = log.logger

    async def run(self) -> None:
        async with VulnCommanderSDK(Config.CONNECTOR_ID, Config.CONNECTOR_PASSWORD) as sdk:
            projects = await sdk.get_projects(ConnectorType.gss)

            if not projects:
                self._log.info(f'Available projects are not found. Skipping current scan...')

            for chunk in batched(projects, Config.PARALLEL_TASKS_COUNT):
                tasks = [asyncio.create_task(self._scan_project(project, sdk)) for project in chunk]
                await asyncio.gather(*tasks)

                self._processed_projects += Config.PARALLEL_TASKS_COUNT
                self._log.info(f'Processed {self._processed_projects}/{len(projects)}.')
                tasks.clear()

    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        async with tempfile.TemporaryDirectory() as temp_dir:
            clone_path, datastore_path, report_path = await self._prepare_paths(project, temp_dir)

            await self._initialize_scanner(clone_path, datastore_path, report_path)
            critical_vulns = await self._process_vulns(project, sdk, report_path, clone_path)

            await sdk.create_or_update_history(
                ConnectorType.gss,
                project.project_id,
                project.last_commit_hash,
                critical=critical_vulns
            )

            subprocess.run(['/bin/rm', '-rf', datastore_path])
            subprocess.run(['/bin/rm', report_path])


    async def _initialize_scanner(
        self,
        clone_path: str,
        datastore_path: str,
        report_path: str
    ) -> None:

        loop = get_running_loop()
        with ThreadPoolExecutor() as pool:
            await loop.run_in_executor(
                pool, self._execute_scanner, clone_path, datastore_path, report_path
            )

    async def _process_vulns(
        self,
        project: ProjectResponseSchema,
        sdk: VulnCommanderSDK,
        report_path: str,
        clone_path: str,
    ) -> int | None:

        async with aiofiles.open(report_path, 'r') as file:
            report = json.loads(await file.read())

        if vulns := await self._parse_report(report, clone_path, project):
            await sdk.process_vulns(vulns, project.vulns)
            return len(vulns)

    async def _parse_report(
        self,
        report: list[dict],
        clone_path: str,
        project: ProjectResponseSchema
    ) -> dict[str, VulnSchema] | None:
        vulns = dict()

        for finding in Vulns(findings=report).findings:
            for match in finding.matches:
                # Parse FirstCommit obj
                first_commit = match.provenance[0].first_commit
                filepath = first_commit.blob_path if first_commit else 'no info'
                commit_id = first_commit.commit_metadata.commit_id if first_commit else 'no info'
                branch = (
                    await self._get_branch(first_commit.commit_metadata.commit_id, clone_path) if first_commit
                    else 'no info'
                )
                # Parse Match obj
                line = str(match.location.source_span.start.line)
                rule_name = match.rule_name
                rule_text_id = match.rule_text_id
                code_snippet = await sanitize(match.snippet.matching)

                project_id = str(project.project_id)
                last_commit_hash = project.last_commit_hash
                connector_type = ConnectorType.gss
                severity = VulnSeverity.critical
                status = VulnStatus.new

                custom_fields = {
                    'commit_id': commit_id,
                    'rule_name': rule_name,
                    'rule_text_id': rule_text_id,
                    'branch': await sanitize(branch)
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

        return vulns

    @staticmethod
    async def _prepare_paths(project: ProjectResponseSchema, temp_dir: str) -> tuple[str, str, str]:
        clone_path = os.path.join(temp_dir, project.name)
        Repo.clone_from(project.clone_url, clone_path)

        scanner_working_directory = os.path.join('gss', 'scaner_working_directory')

        if not os.path.isdir(scanner_working_directory):
            os.mkdir(scanner_working_directory)

        datastore_path = os.path.join(scanner_working_directory, f'{project.project_id}_datastore')
        report_path = os.path.join(scanner_working_directory, f'{project.project_id}_report.json')

        return clone_path, datastore_path, report_path

    @staticmethod
    async def _get_branch(commit_id: str, clone_path: str) -> str:
        result = subprocess.run(
            ['git', 'name-rev', commit_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
            cwd=clone_path
        )

        if branch_info := result.stdout.strip():
            branch_name = branch_info.split()[1]
            if '~' in branch_name:
                branch_name = branch_name.split('~')[0]
            if 'remotes/origin/' in branch_name:
                branch_name = branch_name.split('remotes/origin/')[-1]
            return await sanitize(branch_name)

        return 'no info'

    @staticmethod
    def _execute_scanner(
        clone_path: str,
        datastore_path: str,
        report_path: str
    ) -> None:

        # Execute noseyparker scan
        subprocess.run(
            [
                Config.SCANER_PATH,
                'scan',
                '--quiet',
                clone_path,
                '--datastore',
                datastore_path
            ],
            timeout=60 * 10
        )

        # Generate scan report
        subprocess.run(
            [
                Config.SCANER_PATH,
                'report',
                '--quiet',
                '--datastore',
                datastore_path,
                '--format',
                'json',
                '-o',
                report_path
            ],
            timeout=60 * 30
        )


if __name__ == '__main__':
    time.sleep(5)
    log = GrayLogLogger(Config.GRAYLOG_UDP_PORT)
    scaner = GssScaner(log)
    for next_run in Scheduler(Config.CRON_SCHEDULE):
        log.logger.info('Connector started')
        asyncio.run(scaner.run())
        log.logger.info(f'Successful run. Next run at: {next_run}')

import os
import subprocess
import traceback

from aiofiles import tempfile

from sdk import BaseScanner, VulnCommanderSDK
from sdk.src.utils.helpers import sanitize
from sdk.src.scanner import (
    build_vuln,
    clone_project,
    ensure_scanner_workdir,
    read_json_report
)

from shared.schemas.constants import ConnectorType, VulnSeverity
from shared.schemas.project import ProjectResponseSchema
from shared.schemas.vuln import VulnSchema

from utils.config import Config
from utils.models import Vulns


class GssScaner(BaseScanner):
    def __init__(self, connector_type: ConnectorType, config):
        super().__init__(connector_type, config)

    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        try:
            self._logger.info(f'Processing the project {project.name}.')
            async with tempfile.TemporaryDirectory() as temp_dir:
                clone_path, datastore_path, report_path = self._prepare_paths(project, temp_dir)

                self._execute_scanner(clone_path, datastore_path, report_path)
                critical_vulns_count = await self._process_vulns(project, sdk, report_path, clone_path)

                await sdk.create_or_update_history(
                    ConnectorType.gss,
                    project.project_id,
                    project.last_commit_hash,
                    critical=critical_vulns_count,
                )

                subprocess.run(['/bin/rm', '-rf', datastore_path])
                subprocess.run(['/bin/rm', report_path])
        except Exception:
            self._logger.error(f'Error: {traceback.format_exc()}')

    async def _process_vulns(
        self,
        project: ProjectResponseSchema,
        sdk: VulnCommanderSDK,
        report_path: str,
        clone_path: str,
    ) -> int | None:
        report = await read_json_report(report_path)

        if vulns := await self._parse_report(report, clone_path, project):
            await sdk.process_vulns(vulns, project.vulns)
            return len(vulns)
        return None

    async def _parse_report(
        self,
        report: list[dict],
        clone_path: str,
        project: ProjectResponseSchema,
    ) -> dict[str, VulnSchema] | None:
        vulns = dict()

        for finding in Vulns(findings=report).findings:
            for match in finding.matches:
                first_commit = match.provenance[0].first_commit
                filepath = first_commit.blob_path if first_commit else 'no info'
                commit_id = first_commit.commit_metadata.commit_id if first_commit else 'no info'
                branch = (
                    await self._get_branch(first_commit.commit_metadata.commit_id, clone_path) if first_commit
                    else 'no info'
                )
                line = str(match.location.source_span.start.line)
                rule_name = match.rule_name
                rule_text_id = match.rule_text_id
                code_snippet = await sanitize(match.snippet.matching)

                custom_fields = {
                    'commit_id': commit_id,
                    'rule_name': rule_name,
                    'rule_text_id': rule_text_id,
                    'branch': await sanitize(branch),
                }

                vuln_hash, vuln = await build_vuln(
                    project=project,
                    connector_type=ConnectorType.gss,
                    severity=VulnSeverity.critical,
                    filepath=filepath,
                    line=line,
                    custom_fields=custom_fields,
                    code_snippet=code_snippet,
                )
                vulns[vuln_hash] = vuln

        return vulns

    @staticmethod
    def _prepare_paths(project: ProjectResponseSchema, temp_dir: str) -> tuple[str, str, str]:
        clone_path = clone_project(project, temp_dir)
        workdir = ensure_scanner_workdir('gss')
        datastore_path = os.path.join(workdir, f'{project.project_id}_datastore')
        report_path = os.path.join(workdir, f'{project.project_id}_report.json')
        return clone_path, datastore_path, report_path

    @staticmethod
    async def _get_branch(commit_id: str, clone_path: str) -> str:
        result = subprocess.run(
            ['git', 'name-rev', commit_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
            cwd=clone_path,
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
        report_path: str,
    ) -> None:
        subprocess.run(
            [
                Config.SCANER_PATH,
                'scan',
                '--quiet',
                clone_path,
                '--datastore',
                datastore_path,
            ],
            timeout=60 * 10,
        )

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
                report_path,
            ],
            timeout=60 * 30,
        )


if __name__ == '__main__':
    scanner = GssScaner(ConnectorType.gss, Config())
    scanner.run()

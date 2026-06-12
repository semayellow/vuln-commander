import os
import subprocess
import traceback

from aiofiles import tempfile

from sdk import BaseScanner, VulnCommanderSDK
from sdk.src.scanner import build_vuln, prepare_scan_paths, read_json_report

from shared.schemas.constants import VulnSeverity
from shared.schemas.project import ProjectResponseSchema
from shared.schemas.vuln import VulnSchema

from utils.config import Config
from utils.models import VulnScan


class ScaScaner(BaseScanner):
    def __init__(self, connector_type, config):
        super().__init__(connector_type, config)

    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        try:
            self._logger.info(f'Cloning the project: {project.name}')
            async with tempfile.TemporaryDirectory() as temp_dir:
                clone_path, report_path = prepare_scan_paths(
                    project, temp_dir, 'sca-vuln', '{project_id}_report.json',
                )

                self._execute_scanner(clone_path, report_path)
                severity_counters = await self._process_vulns(project, sdk, report_path)

                await sdk.create_or_update_history(
                    Config.CONNECTOR_TYPE,
                    project.project_id,
                    project.last_commit_hash,
                    **severity_counters
                )

                subprocess.run(['/bin/rm', report_path])
        except Exception:
            self._logger.error(f'Error: {traceback.format_exc()}')

    async def _process_vulns(
        self,
        project: ProjectResponseSchema,
        sdk: VulnCommanderSDK,
        report_path: str,
    ) -> dict[str, int] | dict:
        report = await read_json_report(report_path)
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
        project: ProjectResponseSchema,
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
                        'cvss_score': cvss_score,
                    }

                    vuln_hash, vuln = await build_vuln(
                        project=project,
                        connector_type=Config.CONNECTOR_TYPE,
                        severity=severity,
                        filepath='no info',
                        line='no info',
                        custom_fields=custom_fields,
                    )
                    vulns[vuln_hash] = vuln

        self._logger.info(f'Counters: {VulnScan(**report).severity_counters()}')
        self._logger.info(f'Vulns: {vulns}')
        return VulnScan(**report).severity_counters(), vulns

    def _execute_scanner(
        self,
        clone_path: str,
        report_path: str,
    ) -> None:
        self._logger.info('Converting dependencies')
        self._convert_dependencies(clone_path)

        self._logger.info('Executing scanner dependencies')
        subprocess.run(
            [
                Config.SCANER_PATH,
                'repo',
                '--scanners',
                'vuln',
                '--quiet',
                clone_path,
                '-f',
                'json',
                '-o',
                report_path,
            ],
        )
        self._logger.info('Executing scanner success')

    def _convert_dependencies(self, clone_path: str) -> None:
        try:
            if os.path.isfile(f'{clone_path}/pyproject.toml'):
                subprocess.run(
                    'uv pip compile pyproject.toml > requirements.txt',
                    check=True, cwd=clone_path, shell=True,
                )
        except subprocess.CalledProcessError:
            self._logger.info(
                f'Failed to compile dependencies for the project: {os.path.basename(clone_path)}',
            )

    @staticmethod
    def _get_cvss_score(cvss: dict | None) -> str | float:
        if not cvss:
            return 'no info'
        scores = [score for metric, info in cvss.items() if (score := info.get('V3Score'))]

        if not scores:
            return 'no info'

        return max(scores)


if __name__ == '__main__':
    scanner = ScaScaner(Config.CONNECTOR_TYPE, Config())
    scanner.run()

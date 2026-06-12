import subprocess
import traceback

from aiofiles import tempfile

from sdk import BaseScanner, VulnCommanderSDK
from sdk.src.scanner import build_vuln, prepare_scan_paths, read_json_report

from shared.schemas.constants import ConnectorType, VulnSeverity
from shared.schemas.project import ProjectResponseSchema
from shared.schemas.vuln import VulnSchema

from utils.config import Config
from utils.models import Vulns, SeverityCounters


class IacScaner(BaseScanner):
    def __init__(self, connector_type: ConnectorType, config):
        super().__init__(connector_type, config)

    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        try:
            self._logger.info(f'Scanning the project: {project.name}')
            async with tempfile.TemporaryDirectory() as temp_dir:
                clone_path, report_path = prepare_scan_paths(
                    project, temp_dir, 'iac', '{project_id}',
                )

                self._execute_scanner(clone_path, report_path)
                severity_counters = await self._process_vulns(project, sdk, report_path)

                await sdk.create_or_update_history(
                    ConnectorType.iac,
                    project.project_id,
                    project.last_commit_hash,
                    **severity_counters,
                )

                subprocess.run(['/bin/rm', '-rf', report_path])
        except Exception:
            self._logger.error(f'Error: {traceback.format_exc()}')

    async def _process_vulns(
        self,
        project: ProjectResponseSchema,
        sdk: VulnCommanderSDK,
        report_path: str,
    ) -> SeverityCounters | dict:
        report = await read_json_report(f'{report_path}/results.json')
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

                vuln_hash, vuln = await build_vuln(
                    project=project,
                    connector_type=ConnectorType.iac,
                    severity=severity,
                    filepath=filepath,
                    line=line,
                    custom_fields=custom_fields,
                )
                vulns[vuln_hash] = vuln

        return Vulns(**report).severity_counters.model_dump(), vulns

    @staticmethod
    def _execute_scanner(
        clone_path: str,
        report_path: str,
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
                report_path,
            ],
            timeout=60 * 30,
        )


if __name__ == '__main__':
    scanner = IacScaner(ConnectorType.iac, Config())
    scanner.run()


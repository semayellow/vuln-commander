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
from utils.models import Licenses


class ScaScaner(BaseScanner):
    def __init__(self, connector_type, config):
        super().__init__(connector_type, config)

    async def _scan_project(self, project: ProjectResponseSchema, sdk: VulnCommanderSDK) -> None:
        try:
            self._logger.info(f'Cloning the project: {project.name}')
            async with tempfile.TemporaryDirectory() as temp_dir:
                clone_path, report_path = prepare_scan_paths(
                    project, temp_dir, 'sca', '{project_id}_report.json',
                )

                self._execute_scanner(clone_path, report_path)
                severity_counters = await self._process_vulns(project, sdk, report_path)

                await sdk.create_or_update_history(
                    Config.CONNECTOR_TYPE,
                    project.project_id,
                    project.last_commit_hash,
                    **severity_counters,
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
        if not os.path.isfile(report_path):
            return {}

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

        for result in Licenses(**report).results:
            if result and (entries := result.licenses):
                for entry in entries:
                    severity = VulnSeverity(entry.severity.lower()) if entry.severity != 'UNKNOWN' else VulnSeverity('info')
                    custom_fields = {
                        'package_name': entry.package_name or 'no info',
                        'license_name': entry.name,
                        'link': entry.link or 'no info',
                    }

                    vuln_hash, vuln = await build_vuln(
                        project=project,
                        connector_type=Config.CONNECTOR_TYPE,
                        severity=severity,
                        filepath=entry.filepath,
                        line='no info',
                        custom_fields=custom_fields,
                    )
                    vulns[vuln_hash] = vuln

        return Licenses(**report).severity_counters(), vulns

    def _execute_scanner(
        self,
        clone_path: str,
        report_path: str,
    ) -> None:
        self._logger.info('Installing dependencies')
        dependencies_path = self._install_dependencies(clone_path)

        self._logger.info('Executing scanner dependencies')
        subprocess.run(
            [
                Config.SCANER_PATH,
                'repo',
                '--scanners',
                'license',
                '--license-full',
                '--quiet',
                dependencies_path,
                '-s',
                'UNKNOWN,MEDIUM,HIGH,CRITICAL',
                '-f',
                'json',
                '-o',
                report_path,
            ],
        )
        self._logger.info('Executing scanner success')

    def _install_dependencies(self, clone_path: str) -> str:
        try:
            if os.path.isfile(f'{clone_path}/package.json'):
                self._logger.info(f'JS Project detected, clone path: {clone_path}')

                command = 'ci' if os.path.isfile(f'{clone_path}/package-lock.json') else 'install'

                subprocess.run(
                    f'export NVM_DIR="$HOME/.nvm" '
                    f'&& . "$NVM_DIR/nvm.sh" '
                    f'&& nvm use 22 && npm {command} --ignore-scripts',
                    check=True, shell=True, cwd=clone_path, executable='/bin/bash',
                )
                if os.path.isdir(f'{clone_path}/node_modules'):
                    return f'{clone_path}/node_modules'
            elif os.path.isfile(f'{clone_path}/pyproject.toml'):
                self._logger.info('Python project with project.toml detected')
                subprocess.run(['uv', 'venv'], check=True, cwd=clone_path)
                subprocess.run(['uv', 'pip', 'install', '-r', 'pyproject.toml'], check=True, cwd=clone_path)
            elif os.path.isfile(f'{clone_path}/requirements.txt'):
                self._logger.info('Python project with requirements.txt detected')
                subprocess.run(['uv', 'venv'], check=True, cwd=clone_path)
                subprocess.run(['uv', 'pip', 'install', '-r', 'requirements.txt'], check=True, cwd=clone_path)
        except subprocess.CalledProcessError:
            self._logger.info(f'Failed to install dependencies for the project: {os.path.basename(clone_path)}')

        return clone_path


if __name__ == '__main__':
    scanner = ScaScaner(Config.CONNECTOR_TYPE, Config())
    scanner.run()

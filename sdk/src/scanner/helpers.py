import json
import os
from datetime import datetime, UTC
from typing import Any, Callable

import aiofiles
from git import Repo

from sdk.src.utils.helpers import generate_vuln_hash
from shared.schemas.constants import ConnectorType, VulnSeverity, VulnStatus
from shared.schemas.project import ProjectResponseSchema
from shared.schemas.vuln import VulnSchema


def clone_project(project: ProjectResponseSchema, temp_dir: str) -> str:
    clone_path = os.path.join(temp_dir, project.name)
    Repo.clone_from(project.clone_url, clone_path)
    return clone_path


def ensure_scanner_workdir(scanner_name: str) -> str:
    workdir = os.path.join(scanner_name, 'scaner_working_directory')
    os.makedirs(workdir, exist_ok=True)
    return workdir


def prepare_scan_paths(
    project: ProjectResponseSchema,
    temp_dir: str,
    scanner_name: str,
    report_name: str,
) -> tuple[str, str]:
    clone_path = clone_project(project, temp_dir)
    workdir = ensure_scanner_workdir(scanner_name)
    report_path = os.path.join(workdir, report_name.format(project_id=project.project_id))
    return clone_path, report_path


async def read_json_report(path: str) -> Any:
    async with aiofiles.open(path, 'r') as file:
        return json.loads(await file.read())


async def build_vuln(
    project: ProjectResponseSchema,
    connector_type: ConnectorType,
    severity: VulnSeverity,
    filepath: str,
    line: str,
    custom_fields: dict,
    code_snippet: str = 'no info',
) -> tuple[str, VulnSchema]:
    project_id = str(project.project_id)
    vuln_hash = await generate_vuln_hash(
        project_id=project_id,
        connector_type=connector_type,
        severity=severity,
        filepath=filepath,
        line=line,
        custom_fields=custom_fields,
    )
    return vuln_hash, VulnSchema(
        project_id=project_id,
        last_commit_hash=project.last_commit_hash,
        created_at=datetime.now(UTC),
        connector_type=connector_type,
        severity=severity,
        status=VulnStatus.new,
        filepath=filepath,
        line=line,
        code_snippet=code_snippet,
        custom_fields=custom_fields,
        hash=vuln_hash,
    )




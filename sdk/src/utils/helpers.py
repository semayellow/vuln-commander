import json
import asyncio
import hashlib

import aiohttp

from shared.schemas.constants import ConnectorType, VulnSeverity
from sdk.src.utils import std_log

async def sanitize(text: str) -> str:
    return text.replace('\x00', '')


async def generate_vuln_hash(
    project_id: str,
    connector_type: ConnectorType,
    severity: VulnSeverity,
    filepath: str,
    line: str,
    custom_fields: dict
) -> str:
    return hashlib.md5(
        f'{project_id},'
        f'{connector_type.value},'
        f'{severity.value},'
        f'{filepath},'
        f'{line},'
        f'{json.dumps(custom_fields)}'.encode(),
    ).hexdigest()


def repeat_request(async_function):
    async def wrapper(*args, **kwargs):
        try:
            return await async_function(*args, **kwargs)
        except (aiohttp.ClientError, OSError):
            std_log.warning(f'Failed to bulk process vulns. Repeat request.')
            await asyncio.sleep(1)
            return await async_function(*args, **kwargs)
    return wrapper

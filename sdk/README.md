# Vuln Commander SDK

Client library for building connectors: API authentication, project and vulnerability operations, job scheduling, and Graylog log shipping.

Dependencies: Python ≥ 3.12, `aiohttp`, `pydantic`, and the `vuln-commander-shared` package from `../shared`.

## Installation

In the monorepo, install the SDK with `uv`:

```bash
cd sdk
uv sync --locked
```

In connector Docker images, the working directory is `sdk/` with `PYTHONPATH=/vuln-commander`.

## Imports

```python
from sdk import VulnCommanderSDK, Scheduler
from sdk.src.utils import GrayLogLogger, std_log, get_running_loop
from sdk.src.utils.helpers import sanitize, generate_vuln_hash
from sdk.src.utils.exceptions import RunTimeException
```

## Configuration

| Setting | Where | Default |
|---------|-------|---------|
| API base URL | `sdk/src/utils/config.py` → `Config.API_BASE_URL` | `http://api:8000/api/v1` |
| Connector ID / password | `CONNECTOR_ID`, `CONNECTOR_PASSWORD` in the connector `.env` | — |
| Connector name in logs | `VC_CONNECTOR_NAME` (docker-compose) | — |

For local runs outside Docker, set `API_BASE_URL` to `http://localhost:8000/api/v1`.

---

## `VulnCommanderSDK`

Async HTTP client. Use as a context manager so the `aiohttp` session is opened and closed automatically.

### Constructor

```python
VulnCommanderSDK(
    connector_id: str,
    connector_password: str,
    trust_env: bool = False,
    verify_ssl: str | None = None,
    proxy: str | None = None,
    connector: aiohttp.BaseConnector | None = None,
)
```

| Argument | Description |
|----------|-------------|
| `connector_id` | Connector UUID (username for `POST /auth/`) |
| `connector_password` | Connector password |
| `trust_env` | Honor environment variables for proxy settings |
| `verify_ssl` | Path to a CA certificate for TLS |
| `proxy` | Proxy URL, e.g. `http://user:pass@host:port` |
| `connector` | Custom `aiohttp.BaseConnector` |

### Context manager

```python
async with VulnCommanderSDK(connector_id, password) as sdk:
    ...
```

- `__aenter__` — creates `aiohttp.ClientSession` (60 s timeout)
- `__aexit__` — closes the session

### Authentication (internal)

JWT is fetched automatically before each request (except login itself):

- `POST {API_BASE_URL}/auth` with body `Credentials(username, password)`
- Header `Authorization: Bearer <access_token>`
- Token is refreshed when `expire` from the response is reached

HTTP status ≥ 300 raises `RunTimeException` with the response body and status code.

---

### API methods

#### `get_projects(connector_type: ConnectorType) -> list[ProjectResponseSchema]`

```http
GET /api/v1/projects/{connector_type}
```

Returns projects to scan. Each item includes:

- `project_id`, `name`, `clone_url`, `last_commit_hash`
- `vulns` — dict `{hash: status}` of stored vulnerabilities (for sync)

Requires a connector JWT with scope `devsecops`.

---

#### `create_or_update_project(project: ProjectSchema) -> None`

```http
POST /api/v1/projects
```

Registers or updates a project and its latest commit. Used by the GitHub service connector.

Requires scope `service`.

---

#### `bulk_create_vulns(vulns: list[dict]) -> None`

```http
POST /api/v1/vuln
```

Bulk-creates vulnerabilities. Body is a JSON list of `VulnSchema` objects.

The `@repeat_request` decorator retries once after 1 s on `aiohttp.ClientError` / `OSError`.

---

#### `bulk_update_vulns(vuln_hashes: list[str], vuln_status: VulnStatus) -> None`

```http
PUT /api/v1/vuln?status={vuln_status}
```

Updates status for a list of hashes (e.g. `closed`, `reopened`).

---

#### `process_vulns(actual_vulns: dict[str, VulnSchema], stored_vulns: dict[str, str] | None) -> None`

High-level **synchronization** of findings with the database:

| Situation | Action |
|-----------|--------|
| `stored_vulns` is empty | `bulk_create_vulns` for all `actual_vulns` |
| Hash in actual, not in stored | Create |
| Hash in stored with status `new`/`reopened`, missing in actual | `bulk_update_vulns(..., closed)` |
| Hash in stored with status `closed`, present in actual again | `bulk_update_vulns(..., reopened)` |

Keys in `actual_vulns` are vulnerability hashes (`VulnSchema.hash`).

---

#### `create_or_update_history(...) -> None`

```http
POST /api/v1/connectors/history
```

Records the outcome of a project scan.

```python
await sdk.create_or_update_history(
    connector_type=ConnectorType.gss,
    project_id=project.project_id,
    last_commit_hash=project.last_commit_hash,
    info=0,
    low=1,
    medium=2,
    high=0,
    critical=3,
)
```

Fields `info` through `critical` are optional.

---

## `Scheduler`

Cron schedule iterator (via `cron-converter`).

```python
from sdk import Scheduler

scheduler = Scheduler("0 12 */1 * *")  # every day at 12:00 UTC

for run_at in scheduler:
    # run_at — datetime of the next run
    await run_scan()
```

Each iteration **blocks** the thread (`time.sleep(1)`) until the next run time. Suitable for the main loop in connector `main.py` files.

---

## Helper modules

### `sdk.src.utils.helpers`

| Function | Description |
|----------|-------------|
| `sanitize(text: str) -> str` | Strips NUL characters from strings |
| `generate_vuln_hash(...) -> str` | MD5 vulnerability hash (matches API logic) |
| `repeat_request` | HTTP retry decorator for SDK methods |

### `sdk.src.utils.logger`

| Class | Description |
|-------|-------------|
| `StdLogger` / `std_log` | Stdout logging via loguru |
| `GrayLogLogger(port)` | GELF UDP to host `graylog`, `_vc_connector` from `VC_CONNECTOR_NAME` |

### `sdk.src.utils.exceptions.RunTimeException`

Raised on API HTTP errors; attributes `status_code`, `description`, `json`.

### `sdk.src.utils.models.Credentials`

Pydantic login model: `username`, `password`.

---

## Typical DevSecOps connector loop

```python
import asyncio
from itertools import batched

from sdk import Scheduler, VulnCommanderSDK
from sdk.src.utils import GrayLogLogger
from shared.schemas.constants import ConnectorType
from shared.schemas.vuln import VulnSchema

from utils.config import Config  # CONNECTOR_ID, CONNECTOR_PASSWORD, CRON_SCHEDULE, ...

log = GrayLogLogger(Config.GRAYLOG_UDP_PORT)

async def scan_once():
    async with VulnCommanderSDK(Config.CONNECTOR_ID, Config.CONNECTOR_PASSWORD) as sdk:
        projects = await sdk.get_projects(ConnectorType.gss)
        for chunk in batched(projects, Config.PARALLEL_TASKS_COUNT):
            await asyncio.gather(*[scan_project(sdk, p) for p in chunk])

async def scan_project(sdk, project):
    # 1. git clone into a temp directory
    # 2. run scanner → actual_vulns: dict[str, VulnSchema]
    await sdk.process_vulns(actual_vulns, project.vulns)
    await sdk.create_or_update_history(
        ConnectorType.gss,
        project.project_id,
        project.last_commit_hash,
        critical=len([v for v in actual_vulns.values() if v.severity == "critical"]),
    )

async def main():
    scheduler = Scheduler(Config.CRON_SCHEDULE)
    for _ in scheduler:
        await scan_once()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Data schemas (`shared`)

Connectors and the SDK share Pydantic models:

| Module | Classes |
|--------|---------|
| `shared.schemas.project` | `ProjectSchema`, `ProjectResponseSchema`, `ProjectMetadataSchema`, `CommitMetadataSchema` |
| `shared.schemas.vuln` | `VulnSchema`, `VulnsSchema`, `VulnResponseSchema` |
| `shared.schemas.connector` | `ConnectorHistorySchema`, `ConnectorSchema`, … |
| `shared.schemas.constants` | `ConnectorType`, `VulnStatus`, `VulnSeverity`, … |

Example vulnerability:

```python
from datetime import datetime, UTC
from shared.schemas.constants import ConnectorType, VulnSeverity, VulnStatus
from shared.schemas.vuln import VulnSchema

vuln = VulnSchema(
    project_id=str(project_id),
    last_commit_hash=commit_hash,
    created_at=datetime.now(UTC),
    connector_type=ConnectorType.gss,
    severity=VulnSeverity.high,
    status=VulnStatus.new,
    filepath="src/app.py",
    line="42",
    code_snippet="api_key = '...'",
    custom_fields={"rule_name": "example"},
)
# vuln.hash is computed by the Pydantic serializer
```

---

## Related documentation

- [README.md](../README.md) — platform overview, architecture, Docker Compose setup
- [connectors/connectors_spec.yml](../connectors/connectors_spec.yml) — connector registry for bootstrap

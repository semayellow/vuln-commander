from pathlib import Path
from typing import Any, NamedTuple

import yaml

from api.src.v1.connector.constants import ConnectorScope, ConnectorType


class InitException(Exception):
    def __init__(self, message: str) -> None:
        self.message = message

    def __str__(self):
        return f'[VC DataBase Initialization] {self.message}'


class ConnectorMeta(NamedTuple):
    name: str
    env: str
    scope: ConnectorScope
    type: ConnectorType


CONNECTORS_SPEC_FILE = Path(__file__).resolve().parents[5] / 'connectors' / 'connectors_spec.yml'


def _get_required_string(raw_connector: dict[str, Any], key: str) -> str:
    value = raw_connector.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InitException(f'Invalid connector field "{key}" in connectors_spec.yml')
    return value.strip()


def get_connectors() -> list[ConnectorMeta]:
    if not CONNECTORS_SPEC_FILE.exists():
        raise InitException(f'Connector spec file not found: {CONNECTORS_SPEC_FILE}')

    with CONNECTORS_SPEC_FILE.open('r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    if not isinstance(data, list):
        raise InitException('connectors_spec.yml must contain a list of connectors')

    connectors: list[ConnectorMeta] = []
    for raw_connector in data:
        if not isinstance(raw_connector, dict):
            raise InitException('Each connector in connectors_spec.yml must be an object')

        name = _get_required_string(raw_connector, 'name')
        env = _get_required_string(raw_connector, 'env')
        scope_raw = _get_required_string(raw_connector, 'scope')
        type_raw = _get_required_string(raw_connector, 'type')

        try:
            scope = ConnectorScope(scope_raw)
        except ValueError as exc:
            raise InitException(f'Invalid connector scope "{scope_raw}" for "{name}"') from exc

        try:
            connector_type = ConnectorType(type_raw)
        except ValueError as exc:
            raise InitException(f'Invalid connector type "{type_raw}" for "{name}"') from exc

        connectors.append(
            ConnectorMeta(
                name=name,
                env=env,
                scope=scope,
                type=connector_type,
            )
        )

    return connectors
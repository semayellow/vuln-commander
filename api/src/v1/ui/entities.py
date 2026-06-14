from dataclasses import dataclass


@dataclass
class DashboardStats:
    open_vulnerabilities: int
    active_projects: int
    connectors: int
    scans_today: int


@dataclass
class ProjectRow:
    name: str
    team: str
    status: str
    last_commit_date: str
    open_vulns: int


@dataclass
class ConnectorRow:
    name: str
    scope: str
    status: str
    status_class: str
    last_run: str

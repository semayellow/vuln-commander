from enum import Enum


class ConnectorScope(Enum):
    service = "service"
    devsecops = "devsecops"


class ConnectorType(Enum):
    iac = "iac"
    gss = "gss"
    sca_license = "sca_license"
    sca_vuln = "sca_vuln"
    github = "github"


class ConnectorLastRunStatus(Enum):
    success = "success"
    failure = "failure"


class ProjectStatus(Enum):
    active = "active"
    archived = "archived"


class UserTeam(Enum):
    ti = "ti"
    sandbox = "sandbox"


class VulnSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class VulnStatus(str, Enum):
    new = "new"
    awaiting_review = "awaiting_review"
    closed = "closed"
    false_positive = "false_positive"
    reopened = "reopened"

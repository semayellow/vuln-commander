from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    package_name: str = Field(alias="PkgName")
    installed_version: str = Field(alias="InstalledVersion")
    fixed_version: str | None = Field(None, alias="FixedVersion")
    status: str = Field(alias="Status")
    recommendation_url: str | None = Field(None, alias="PrimaryURL")
    title: str = Field(alias="Title")
    description: str = Field(alias="Description")
    severity: str = Field(alias="Severity")
    cvss: dict | None = Field(None, alias="CVSS")


class Result(BaseModel):
    package_manager: str = Field(alias="Type")
    vulnerabilities: list[Vulnerability] = Field(None, alias="Vulnerabilities")


class VulnScan(BaseModel):
    results: list[Result] = Field(None, alias="Results")

    def severity_counters(self) -> dict[str, int]:
        counters = {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

        for results in self.results:
            if entries := results.vulnerabilities:
                for entry in entries:
                    if (severity := entry.severity.lower()) in counters:
                        counters[severity] += 1
                    else:
                        counters['info'] += 1

        return counters

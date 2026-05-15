from pydantic import BaseModel, Field


class License(BaseModel):
    severity: str = Field(alias="Severity")
    package_name: str | None = Field(None, alias="PkgName")
    filepath: str = Field(alias="FilePath")
    name: str = Field(alias="Name")
    link: str = Field(alias='Link')


class Result(BaseModel):
    licenses: list[License] = Field(None, alias="Licenses")


class Licenses(BaseModel):
    results: list[Result] = Field(None, alias="Results")

    def severity_counters(self) -> dict[str, int]:
        counters = {'info': 0, 'medium': 0, 'high': 0, 'critical': 0}

        for results in self.results:
            if entries := results.licenses:
                for entry in entries:
                    if (severity := entry.severity.lower()) in counters:
                        counters[severity] += 1
                    else:
                        counters['info'] += 1

        return counters

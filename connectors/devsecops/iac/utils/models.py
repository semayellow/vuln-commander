from pydantic import BaseModel, Field


class SeverityCounters(BaseModel):
    critical: int = Field(alias='CRITICAL', default=None)
    high: int = Field(alias='HIGH', default=None)
    info: int = Field(alias='INFO', default=None)
    low: int = Field(alias='LOW', default=None)
    medium: int = Field(alias='MEDIUM', default=None)


class QueryFile(BaseModel):
    file_name: str
    line: int
    search_key: str
    search_line: int
    expected_value: str
    actual_value: str


class Query(BaseModel):
    query_name: str
    query_id: str
    query_url: str
    severity: str
    platform: str
    cwe: str
    category: str
    description: str
    files: list[QueryFile]


class Vulns(BaseModel):
    severity_counters: SeverityCounters
    queries: list[Query]

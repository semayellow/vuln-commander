import json
from typing import List, Optional, Union
from pydantic import BaseModel, Field


class SourcePosition(BaseModel):
    line: int


class SourceSpan(BaseModel):
    start: SourcePosition


class Location(BaseModel):
    source_span: SourceSpan


class Snippet(BaseModel):
    matching: str


class CommitMetadata(BaseModel):
    commit_id: str


class FirstCommit(BaseModel):
    commit_metadata: CommitMetadata
    blob_path: str


class ProvenanceItem(BaseModel):
    first_commit: Optional[FirstCommit] = None


class MatchModel(BaseModel):
    location: Location
    snippet: Snippet
    provenance: List[ProvenanceItem]
    rule_name: str
    rule_text_id: str


class Vuln(BaseModel):
    matches: List[MatchModel]


class Vulns(BaseModel):
    findings: list[Vuln] = Field(default=None)

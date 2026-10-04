from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: Literal["low", "medium", "high"]
    summary: str = Field(min_length=1, max_length=1000)
    references: list[str] = Field(min_length=1, max_length=20)

class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=2000)
    findings: list[Finding] = Field(min_length=1, max_length=10)
    timeline: list[str] = Field(max_length=30)
    recommend_disable: bool

def validate_references(report: Report, references: set[str]) -> Report:
    if any(ref not in references for finding in report.findings for ref in finding.references):
        raise ValueError("ungrounded citation")
    if any(len(line) > 500 for line in report.timeline):
        raise ValueError("timeline too long")
    return report

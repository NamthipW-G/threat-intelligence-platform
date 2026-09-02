from enum import Enum

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCCreate(BaseModel):
    type: IOCType
    value: str = Field(min_length=1, max_length=2048)
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    source: str = Field(min_length=1, max_length=255)
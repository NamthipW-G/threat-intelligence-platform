from pydantic import BaseModel, Field


class ThreatActorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    origin: str | None = Field(default=None, max_length=255)
    motivation: str | None = Field(default=None, max_length=255)
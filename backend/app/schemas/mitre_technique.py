from pydantic import BaseModel, Field


class MitreTechniqueCreate(BaseModel):
    technique_id: str = Field(min_length=2, max_length=20)
    name: str = Field(min_length=1, max_length=255)
    tactic: str = Field(min_length=1, max_length=255)
    description: str | None = None
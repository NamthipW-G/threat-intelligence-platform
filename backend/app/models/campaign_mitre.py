from sqlalchemy import Column, ForeignKey, Integer, Table

from app.database import Base


campaign_mitre_techniques = Table(
    "campaign_mitre_techniques",
    Base.metadata,
    Column(
        "campaign_id",
        Integer,
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "mitre_technique_id",
        Integer,
        ForeignKey("mitre_techniques.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)
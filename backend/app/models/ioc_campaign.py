from sqlalchemy import Column, ForeignKey, Integer, Table

from app.database import Base


ioc_campaigns = Table(
    "ioc_campaigns",
    Base.metadata,
    Column(
        "ioc_id",
        Integer,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "campaign_id",
        Integer,
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)
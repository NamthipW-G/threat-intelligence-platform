from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        unique=True,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.models import IOC
from app.schemas.ioc import IOCCreate

app = FastAPI(
    title="Threat Intelligence Operations Platform",
    description="REST API for collecting, managing, and analysing threat intelligence.",
    version="1.0.0",
)

Base.metadata.create_all(bind=engine)

@app.get("/")
def root():
    return {
        "service": "Threat Intelligence Operations Platform",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/iocs")
def create_ioc(
    ioc: IOCCreate,
    db: Session = Depends(get_db),
):
    db_ioc = IOC(
        type=ioc.type.value,
        value=ioc.value,
        severity=ioc.severity.value,
        confidence=ioc.confidence,
        source=ioc.source,
    )

    db.add(db_ioc)
    db.commit()
    db.refresh(db_ioc)

    return {
        "message": "IOC created successfully",
        "ioc": {
            "id": db_ioc.id,
            "type": db_ioc.type,
            "value": db_ioc.value,
            "severity": db_ioc.severity,
            "confidence": db_ioc.confidence,
            "source": db_ioc.source,
            "created_at": db_ioc.created_at,
        },
    }
@app.get("/iocs")
def get_iocs(
    type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(IOC)

    if type:
        query = query.filter(IOC.type == type)

    if severity:
        query = query.filter(IOC.severity == severity)

    if search:
        query = query.filter(IOC.value.ilike(f"%{search}%"))

    iocs = query.order_by(IOC.created_at.desc()).all()

    return iocs


@app.get("/iocs/{ioc_id}")
def get_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    return ioc
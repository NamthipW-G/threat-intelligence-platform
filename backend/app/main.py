from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

from app.models.threat_actor import ThreatActor
from app.schemas.threat_actor import ThreatActorCreate
from app.services.risk_scoring import calculate_risk_score
from app.database import Base, engine, get_db
from app.models import IOC
from app.schemas.ioc import IOCCreate
from app.models.campaign import Campaign
from app.schemas.campaign import CampaignCreate

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

@app.get("/iocs/{ioc_id}/risk")
def get_ioc_risk(
    ioc_id: int,
    db: Session = Depends(get_db),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    risk_score = calculate_risk_score(
        severity=ioc.severity,
        confidence=ioc.confidence,
    )

    if risk_score >= 85:
        risk_level = "critical"
    elif risk_score >= 70:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "ioc_id": ioc.id,
        "value": ioc.value,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity": ioc.severity,
        "confidence": ioc.confidence,
    }
@app.post("/threat-actors")
def create_threat_actor(
    actor_data: ThreatActorCreate,
    db: Session = Depends(get_db),
):
    existing_actor = (
        db.query(ThreatActor)
        .filter(ThreatActor.name == actor_data.name)
        .first()
    )

    if existing_actor:
        raise HTTPException(
            status_code=409,
            detail="Threat actor already exists",
        )

    actor = ThreatActor(
        name=actor_data.name,
        description=actor_data.description,
        origin=actor_data.origin,
        motivation=actor_data.motivation,
    )

    db.add(actor)
    db.commit()
    db.refresh(actor)

    return actor


@app.get("/threat-actors")
def get_threat_actors(
    db: Session = Depends(get_db),
):
    return (
        db.query(ThreatActor)
        .order_by(ThreatActor.created_at.desc())
        .all()
    )

@app.post("/campaigns")
def create_campaign(
    campaign_data: CampaignCreate,
    db: Session = Depends(get_db),
):
    actor = (
        db.query(ThreatActor)
        .filter(ThreatActor.id == campaign_data.threat_actor_id)
        .first()
    )

    if not actor:
        raise HTTPException(
            status_code=404,
            detail="Threat actor not found",
        )

    campaign = Campaign(
        name=campaign_data.name,
        description=campaign_data.description,
        threat_actor_id=campaign_data.threat_actor_id,
    )

    db.add(campaign)
    db.commit()
    db.refresh(campaign)

    return campaign


@app.get("/campaigns")
def get_campaigns(
    db: Session = Depends(get_db),
):
    return (
        db.query(Campaign)
        .order_by(Campaign.created_at.desc())
        .all()
    )
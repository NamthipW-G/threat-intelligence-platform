from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware

from app.models.threat_actor import ThreatActor
from app.schemas.threat_actor import ThreatActorCreate
from app.services.risk_scoring import calculate_risk_score
from app.database import Base, engine, get_db
from app.models import IOC
from app.schemas.ioc import IOCCreate
from app.models.campaign import Campaign
from app.schemas.campaign import CampaignCreate
from app.models.mitre_technique import MitreTechnique
from app.schemas.mitre_technique import MitreTechniqueCreate
from app.models.campaign_mitre import campaign_mitre_techniques
from app.models.ioc_campaign import ioc_campaigns

app = FastAPI(
    title="Threat Intelligence Operations Platform",
    description="REST API for collecting, managing, and analysing threat intelligence.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

@app.post("/mitre-techniques")
def create_mitre_technique(
    technique_data: MitreTechniqueCreate,
    db: Session = Depends(get_db),
):
    existing_technique = (
        db.query(MitreTechnique)
        .filter(
            MitreTechnique.technique_id
            == technique_data.technique_id
        )
        .first()
    )

    if existing_technique:
        raise HTTPException(
            status_code=409,
            detail="MITRE technique already exists",
        )

    technique = MitreTechnique(
        technique_id=technique_data.technique_id,
        name=technique_data.name,
        tactic=technique_data.tactic,
        description=technique_data.description,
    )

    db.add(technique)
    db.commit()
    db.refresh(technique)

    return technique


@app.get("/mitre-techniques")
def get_mitre_techniques(
    db: Session = Depends(get_db),
):
    return (
        db.query(MitreTechnique)
        .order_by(MitreTechnique.technique_id.asc())
        .all()
    )
@app.post("/campaigns/{campaign_id}/techniques/{technique_id}")
def add_technique_to_campaign(
    campaign_id: int,
    technique_id: int,
    db: Session = Depends(get_db),
):
    campaign = (
        db.query(Campaign)
        .filter(Campaign.id == campaign_id)
        .first()
    )

    if not campaign:
        raise HTTPException(
            status_code=404,
            detail="Campaign not found",
        )

    technique = (
        db.query(MitreTechnique)
        .filter(MitreTechnique.id == technique_id)
        .first()
    )

    if not technique:
        raise HTTPException(
            status_code=404,
            detail="MITRE technique not found",
        )

    existing_link = db.execute(
        campaign_mitre_techniques.select().where(
            (campaign_mitre_techniques.c.campaign_id == campaign_id)
            & (
                campaign_mitre_techniques.c.mitre_technique_id
                == technique_id
            )
        )
    ).first()

    if existing_link:
        raise HTTPException(
            status_code=409,
            detail="Technique already linked to campaign",
        )

    db.execute(
        campaign_mitre_techniques.insert().values(
            campaign_id=campaign_id,
            mitre_technique_id=technique_id,
        )
    )

    db.commit()

    return {
        "message": "MITRE technique linked to campaign",
        "campaign": campaign.name,
        "technique_id": technique.technique_id,
        "technique_name": technique.name,
    }

@app.get("/campaigns/{campaign_id}/techniques")
def get_campaign_techniques(
    campaign_id: int,
    db: Session = Depends(get_db),
):
    campaign = (
        db.query(Campaign)
        .filter(Campaign.id == campaign_id)
        .first()
    )

    if not campaign:
        raise HTTPException(
            status_code=404,
            detail="Campaign not found",
        )

    techniques = (
        db.query(MitreTechnique)
        .join(
            campaign_mitre_techniques,
            MitreTechnique.id
            == campaign_mitre_techniques.c.mitre_technique_id,
        )
        .filter(
            campaign_mitre_techniques.c.campaign_id
            == campaign_id
        )
        .all()
    )

    return {
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "techniques": techniques,
    }

@app.post("/iocs/{ioc_id}/campaigns/{campaign_id}")
def link_ioc_to_campaign(
    ioc_id: int,
    campaign_id: int,
    db: Session = Depends(get_db),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    campaign = (
        db.query(Campaign)
        .filter(Campaign.id == campaign_id)
        .first()
    )

    if not campaign:
        raise HTTPException(
            status_code=404,
            detail="Campaign not found",
        )

    existing_link = db.execute(
        ioc_campaigns.select().where(
            (ioc_campaigns.c.ioc_id == ioc_id)
            & (ioc_campaigns.c.campaign_id == campaign_id)
        )
    ).first()

    if existing_link:
        raise HTTPException(
            status_code=409,
            detail="IOC already linked to campaign",
        )

    db.execute(
        ioc_campaigns.insert().values(
            ioc_id=ioc_id,
            campaign_id=campaign_id,
        )
    )

    db.commit()

    return {
        "message": "IOC linked to campaign",
        "ioc": ioc.value,
        "campaign": campaign.name,
    }

@app.get("/iocs/{ioc_id}/intelligence")
def get_ioc_intelligence(
    ioc_id: int,
    db: Session = Depends(get_db),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    campaigns = (
        db.query(Campaign)
        .join(
            ioc_campaigns,
            Campaign.id == ioc_campaigns.c.campaign_id,
        )
        .filter(ioc_campaigns.c.ioc_id == ioc_id)
        .all()
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

    campaign_data = []

    for campaign in campaigns:
        actor = (
            db.query(ThreatActor)
            .filter(ThreatActor.id == campaign.threat_actor_id)
            .first()
        )

        techniques = (
            db.query(MitreTechnique)
            .join(
                campaign_mitre_techniques,
                MitreTechnique.id
                == campaign_mitre_techniques.c.mitre_technique_id,
            )
            .filter(
                campaign_mitre_techniques.c.campaign_id
                == campaign.id
            )
            .all()
        )

        campaign_data.append(
            {
                "campaign_id": campaign.id,
                "campaign_name": campaign.name,
                "threat_actor": actor.name if actor else None,
                "techniques": [
                    {
                        "technique_id": technique.technique_id,
                        "name": technique.name,
                        "tactic": technique.tactic,
                    }
                    for technique in techniques
                ],
            }
        )

    return {
        "ioc": {
            "id": ioc.id,
            "type": ioc.type,
            "value": ioc.value,
            "severity": ioc.severity,
            "confidence": ioc.confidence,
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
        },
        "campaigns": campaign_data,
    }
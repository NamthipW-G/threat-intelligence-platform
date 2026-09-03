from fastapi import FastAPI
from app.database import Base, engine
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
def create_ioc(ioc: IOCCreate):
    return {
        "message": "IOC received successfully",
        "ioc": ioc,
    }
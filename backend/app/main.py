from fastapi import FastAPI

app = FastAPI(
    title="Threat Intelligence Operations Platform",
    description="REST API for collecting, managing, and analysing threat intelligence.",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "service": "Threat Intelligence Operations Platform",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }
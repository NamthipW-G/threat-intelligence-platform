# Threat Intelligence Operations Platform

A full-stack cybersecurity platform for collecting, correlating and analysing threat intelligence.

The platform enables security analysts to manage Indicators of Compromise (IOCs), associate them with threat actors and campaigns, map adversary behaviour to MITRE ATT&CK techniques, and investigate correlated intelligence through an analyst dashboard.

## Key Features

- Manage Indicators of Compromise including domains, IP addresses, URLs and SHA-256 hashes
- Validate threat intelligence data using Pydantic
- Search and filter IOCs by severity, type and indicator value
- Calculate explainable IOC risk scores using severity and confidence
- Manage threat actors and campaigns
- Map campaigns to MITRE ATT&CK techniques
- Correlate IOCs with campaigns and threat actors
- Investigate IOC intelligence from a React analyst dashboard
- Loading and API error handling
- Automated backend and frontend tests

## Intelligence Correlation

The platform correlates multiple security entities to provide analysts with contextual intelligence:

```text
Indicator of Compromise
        |
        +---- Risk Score
        |
        v
     Campaign
        |
        +---- Threat Actor
        |
        v
 MITRE ATT&CK Techniques
```

Example investigation:

```text
secure-login-example.com
        |
        +---- Risk Score: 80 / HIGH
        |
        v
Operation Shadow Login
        |
        +---- Threat Actor: APT Example Group
        |
        v
T1566.002 - Spearphishing Link
Initial Access
```

## Architecture

```text
+----------------------------+
| React + TypeScript         |
| Analyst Dashboard          |
+-------------+--------------+
              |
              | REST API
              v
+----------------------------+
| FastAPI                    |
| API & Application Logic    |
+-------------+--------------+
              |
       +------+------+
       |             |
       v             v
 Risk Scoring   Correlation Engine
       |             |
       +------+------+
              |
              v
+----------------------------+
| SQLAlchemy                 |
+-------------+--------------+
              |
              v
+----------------------------+
| PostgreSQL                 |
| Threat Intelligence Data   |
+----------------------------+
```

## Technology Stack

### Backend
- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Pydantic
- pytest

### Frontend
- React
- TypeScript
- Vite
- Vitest
- React Testing Library

### Engineering
- REST APIs
- Relational data modelling
- Many-to-many relationships
- Input validation
- Error handling
- Unit and API testing
- Git and GitHub

## Data Model

The platform models relationships between:

- Indicators of Compromise
- Threat Actors
- Campaigns
- MITRE ATT&CK Techniques

Campaigns can use multiple MITRE ATT&CK techniques, while individual techniques can appear across multiple campaigns.

IOCs can also be associated with multiple campaigns, allowing the platform to build correlated intelligence around suspicious infrastructure.

## Risk Scoring

IOC risk is calculated using an intentionally simple and explainable portfolio scoring model:

```text
Risk Score =
(Severity Score x 0.60) +
(Confidence x 0.40)
```

Severity weights:

| Severity | Score |
|---|---:|
| Low | 25 |
| Medium | 50 |
| High | 75 |
| Critical | 100 |

The scoring model is designed to demonstrate explainable security-analysis logic and is not intended to represent an industry-standard maliciousness score.

## API

FastAPI automatically exposes interactive OpenAPI documentation at:

```text
http://127.0.0.1:8000/docs
```

Example endpoints include:

```text
GET  /health
POST /iocs
GET  /iocs
GET  /iocs/{ioc_id}
GET  /iocs/{ioc_id}/risk
GET  /iocs/{ioc_id}/intelligence

POST /threat-actors
GET  /threat-actors

POST /campaigns
GET  /campaigns

POST /mitre-techniques
GET  /mitre-techniques
```

## Running Locally

### 1. Backend

Create a PostgreSQL database named:

```text
threat_intel
```

Create `backend/.env`:

```text
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/threat_intel
```

Then:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

### 2. Frontend

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

## Testing

Backend:

```powershell
cd backend
pytest
```

The backend test suite covers risk-scoring logic, health checks and API validation.

Frontend:

```powershell
cd frontend
npx vitest run
```

The frontend test suite covers IOC rendering, analyst investigation flows and API error handling.

## Security Concepts Demonstrated

This project provides practical implementation evidence for:

- Indicators of Compromise (IOC)
- Threat intelligence correlation
- Threat actors
- Threat campaigns
- MITRE ATT&CK techniques
- Risk scoring
- Analyst investigation workflows
- Security-oriented relational data modelling

## Future Improvements

Potential production extensions include:

- Authentication and role-based access control
- External threat-feed ingestion
- IOC enrichment services
- Pagination and advanced search
- Database migrations with Alembic
- Background processing
- Audit logging
- Containerisation and CI/CD
- Cloud deployment

## Project Purpose

This project was built as a portfolio demonstration of full-stack software engineering applied to cybersecurity and threat intelligence.

It combines Python backend engineering, REST API design, PostgreSQL relational modelling, React and TypeScript frontend development, automated testing, and domain-specific threat intelligence logic.
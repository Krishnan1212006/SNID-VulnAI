# VulnAI-DevSecOps Platform

An intelligent, AI-assisted cybersecurity platform demonstrating next-generation DevSecOps, Continuous Monitoring, Machine Learning Anomaly Detection, and automated Security Gates over active web and IoT targets.

## System Architecture

```mermaid
graph TD
    %% Define System Actors
    actor User as "Security Engineer"
    actor CI as "CI/CD Pipeline (GitHub Actions)"
    actor IoT as "IoT Subnets / Sensors"
    
    %% Define Frontend Infrastructure
    subgraph Frontend ["React SPA (Nginx)"]
        UI_Dash[Dashboard]
        UI_Scan[Vuln Scans]
        UI_Monitor[Traffic Monitoring]
        UI_DevSecOps[DevSecOps Gates]
    end
    
    %% Define Backend Infrastructure
    subgraph Backend ["FastAPI / Python (Uvicorn)"]
        API_Scan[Scanning Engine]
        API_AI[AI / IsolationForest]
        API_Risk[Risk Formula Engine]
        API_DevSecOps[Security Release Gates]
        WS_Core[WebSocket Manager]
    end
    
    %% Define Database Infrastructure
    subgraph DB ["Neon Postgres"]
        Coll_Assets[Assets]
        Coll_Vulnerabilities[Vulnerabilities]
        Coll_Pipelines[Pipeline Runs]
        Coll_Incidents[Correlated Incidents]
    end
    
    %% Define Connections
    User -.-> |Uses| Frontend
    CI -.-> |Triggers Webhooks| API_DevSecOps
    IoT -.-> |Streams Traffic| API_AI
    
    UI_Dash <--> |WebSockets| WS_Core
    UI_Scan <--> |REST| API_Scan
    UI_DevSecOps <--> |REST| API_DevSecOps
    UI_Monitor <--> |REST| API_AI
    
    API_Scan <--> Coll_Vulnerabilities
    API_Risk <--> Coll_Assets
    API_DevSecOps <--> Coll_Pipelines
    API_AI <--> Coll_Incidents
```

## Core Modules & Capabilities

1. **Passive Vulnerability Scanning**: Scans web modules without payloads against predefined SSRF IP blockers actively tracking vulnerabilities against OWASP mappings securely.
2. **AI Metric Correlation (Isolation Forest)**: Trains models processing bandwidth bytes and packet connections mapping outliers automatically and dynamically resolving them as internal incidents!
3. **Enterprise Dashboard**: Renders seamless connections dynamically mapping bandwidth throughput globally evaluating overall risk metrics gracefully.
4. **DevSecOps Release Integrations**: Embeds logic tracking severity counts dynamically enforcing security thresholds natively, halting CI/CD runs instantly via webhook integrations!

## Deployment Guide 🚀

Deploying this architecture is entirely modular via **Docker Compose**. Set `DATABASE_URL` in your shell or the project-root `.env` file to your Neon Postgres connection string before starting the backend. Use the pooled connection string for application traffic.

### 1. Local Network Instantiation
Clone the project locally and instantiate environmental bindings explicitly mapping ports natively:
```bash
docker-compose up --build -d
```
That launches the application containers:
- **`vulnai-backend`**: FastAPI endpoints spanning across `http://localhost:8000/api`, connected to Neon Postgres.
- **`vulnai-frontend`**: React App available instantly via `http://localhost:5173`.

### 2. Loading the Demo Topology
Populate the backend directly validating integrations natively:
```bash
docker exec -it vulnai-backend python seed_final.py
```
This script handles pipeline generations evaluating tests natively generating fully mapped events triggering root incident mappings! Enjoy.

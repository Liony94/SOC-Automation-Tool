from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.routes import enrichment, health

app = FastAPI(
    title="Security Automation API",
    description="API pour l'enrichissement et l'automatisation de la sécurité",
    version="1.0.0"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(health.router, tags=["Health"])
app.include_router(enrichment.router, prefix="/api/v1/enrichment", tags=["Enrichment"]) 
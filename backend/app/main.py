"""WebVAST FastAPI application entry point.

Run with:  uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes import router
from app.config import settings
from app.models import database as db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    yield


app = FastAPI(
    title="WebVAST API",
    description="Web Vulnerability Assessment & Scanning Toolkit",
    version=__version__,
    lifespan=lifespan,
)

# The React frontend runs on a different origin (the Vite dev server in
# development, or a hosted deployment in production). Allowed origins come from
# config (local-dev defaults + anything in WEBVAST_CORS_ORIGINS).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
async def root() -> dict:
    return {"name": "WebVAST API", "version": __version__, "docs": "/docs"}

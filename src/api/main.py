#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ForensicHunter Enterprise API

RESTful API for enterprise forensic operations.
Authentication is handled via Bearer token validated against the
API_SECRET_KEY environment variable (required in production).
"""

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import structlog
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    WebSocket,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.enterprise_config import EnterpriseConfig, ENTERPRISE_MODULES, ENTERPRISE_TARGETS
from ..core.enterprise_collector import EnterpriseCollector

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
_API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "")
_ENV            = os.environ.get("FORENSICHUNTER_ENV", "production")
_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if o.strip()
] or (["*"] if _ENV == "development" else [])

if _ENV != "development" and not _API_SECRET_KEY:
    raise RuntimeError(
        "API_SECRET_KEY environment variable is required in production. "
        "Set it to a strong secret before starting the server."
    )

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class CollectionRequest(BaseModel):
    targets: List[str] = Field(..., description="Forensic targets to collect")
    destination: str   = Field(..., description="Output directory")
    case_name:    Optional[str] = Field(None, description="Case name")
    investigator: Optional[str] = Field(None, description="Investigator name")
    compress:  bool = Field(False, description="Compress collected files")
    encrypt:   bool = Field(False, description="Encrypt collected files")
    parallel_workers: Optional[int] = Field(None, description="Parallel workers")


class ModuleRequest(BaseModel):
    modules:       List[str] = Field(..., description="Analysis modules to execute")
    evidence_path: str       = Field(..., description="Path to evidence directory")
    timeout:  int = Field(1800, description="Per-module timeout in seconds")
    parallel: int = Field(1,    description="Parallel module count")


class CollectionStatus(BaseModel):
    collection_id: str
    status: str
    progress: float
    start_time: datetime
    estimated_completion: Optional[datetime] = None
    files_collected: int
    bytes_collected: int
    current_target: Optional[str] = None
    error_message:  Optional[str] = None


class SystemStatus(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    active_collections: int
    system_resources: Dict[str, Any]
    dependencies_status: Dict[str, bool]


class InvestigationRequest(BaseModel):
    case_name:    str       = Field(..., description="Case name")
    investigator: str       = Field(..., description="Investigator name")
    targets:  List[str]     = Field(default_factory=lambda: ["all"])
    modules:  List[str]     = Field(default_factory=lambda: ["all"])
    destination: str        = Field(..., description="Investigation output directory")
    memory_dump: Optional[str] = Field(None, description="Path to memory dump")
    report_formats: List[str]  = Field(default_factory=lambda: ["json", "html"])


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ForensicHunter Enterprise API",
    description="Professional Digital Forensics Platform",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ---------------------------------------------------------------------------
# Global state (replace with a database in a multi-instance deployment)
# ---------------------------------------------------------------------------
config            = EnterpriseConfig()
active_collections: Dict[str, Dict] = {}
system_start_time = time.time()

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
security = HTTPBearer()


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, str]:
    """Validate Bearer token against API_SECRET_KEY."""
    if not _API_SECRET_KEY or credentials.credentials != _API_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"user": "api", "permissions": ["all"]}


# ---------------------------------------------------------------------------
# Health & status
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/status", response_model=SystemStatus, tags=["System"])
async def get_system_status():
    deps: Dict[str, bool] = {}
    for dep in ("volatility3", "yara", "psutil", "fastapi"):
        try:
            __import__(dep.replace("-", "_"))
            deps[dep] = True
        except ImportError:
            deps[dep] = False

    resources: Dict[str, Any] = {}
    try:
        resources = {
            "cpu_percent":    psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage":     dict(psutil.disk_usage("/")),
            "load_average":   list(os.getloadavg()) if hasattr(os, "getloadavg") else [0, 0, 0],
        }
    except Exception:
        resources = {"error": "Unable to retrieve system resources"}

    return SystemStatus(
        status="operational",
        version="2.0.0",
        uptime_seconds=time.time() - system_start_time,
        active_collections=len(active_collections),
        system_resources=resources,
        dependencies_status=deps,
    )


# ---------------------------------------------------------------------------
# Targets & modules catalog
# ---------------------------------------------------------------------------
@app.get("/api/targets", tags=["Catalog"])
async def list_targets():
    return {"targets": ENTERPRISE_TARGETS, "count": len(ENTERPRISE_TARGETS)}


@app.get("/api/targets/{target_name}", tags=["Catalog"])
async def get_target(target_name: str):
    if target_name not in ENTERPRISE_TARGETS:
        raise HTTPException(status_code=404, detail="Target not found")
    return ENTERPRISE_TARGETS[target_name]


@app.get("/api/modules", tags=["Catalog"])
async def list_modules():
    return {"modules": ENTERPRISE_MODULES, "count": len(ENTERPRISE_MODULES)}


@app.get("/api/modules/{module_name}", tags=["Catalog"])
async def get_module(module_name: str):
    if module_name not in ENTERPRISE_MODULES:
        raise HTTPException(status_code=404, detail="Module not found")
    return ENTERPRISE_MODULES[module_name]


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------
@app.post("/api/collections", tags=["Collections"])
async def start_collection(
    request: CollectionRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(verify_token),
):
    invalid = [t for t in request.targets if t not in ENTERPRISE_TARGETS and t != "all"]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown targets: {', '.join(invalid)}")

    collector     = EnterpriseCollector(config)
    collection_id = collector.collection_id

    active_collections[collection_id] = {
        "id":         collection_id,
        "status":     "starting",
        "progress":   0.0,
        "start_time": datetime.utcnow(),
        "request":    request.model_dump(),
        "user":       user["user"],
        "collector":  collector,
    }

    background_tasks.add_task(_run_collection, collection_id, request)
    log.info("collection_started", id=collection_id, user=user["user"])
    return {"collection_id": collection_id, "status": "started"}


async def _run_collection(collection_id: str, request: CollectionRequest):
    col = active_collections[collection_id]["collector"]
    try:
        active_collections[collection_id]["status"] = "collecting"
        targets = list(ENTERPRISE_TARGETS.keys()) if "all" in request.targets else request.targets

        def _progress(current, total):
            if collection_id in active_collections:
                active_collections[collection_id]["progress"] = (current / total) * 100

        result = await col.collect_targets(
            target_names=targets,
            output_path=request.destination,
            progress_callback=_progress,
        )
        active_collections[collection_id].update(
            status="completed", progress=100.0,
            end_time=datetime.utcnow(), result=result,
            files_collected=col.stats["files_collected"],
            bytes_collected=col.stats["bytes_collected"],
        )
        log.info("collection_completed", id=collection_id)
    except Exception as exc:
        active_collections[collection_id].update(
            status="failed", error_message=str(exc), end_time=datetime.utcnow()
        )
        log.error("collection_failed", id=collection_id, error=str(exc))


@app.get("/api/collections", tags=["Collections"])
async def list_collections(user: dict = Depends(verify_token)):
    return {
        "collections": [
            {
                "id":         cid,
                "status":     info["status"],
                "start_time": info["start_time"],
                "progress":   info.get("progress", 0),
                "user":       info.get("user"),
            }
            for cid, info in active_collections.items()
        ],
        "count": len(active_collections),
    }


@app.get("/api/collections/{collection_id}", response_model=CollectionStatus, tags=["Collections"])
async def get_collection(collection_id: str, user: dict = Depends(verify_token)):
    info = active_collections.get(collection_id)
    if not info:
        raise HTTPException(status_code=404, detail="Collection not found")
    return CollectionStatus(
        collection_id=collection_id,
        status=info["status"],
        progress=info.get("progress", 0.0),
        start_time=info["start_time"],
        estimated_completion=info.get("estimated_completion"),
        files_collected=info.get("files_collected", 0),
        bytes_collected=info.get("bytes_collected", 0),
        current_target=info.get("current_target"),
        error_message=info.get("error_message"),
    )


@app.delete("/api/collections/{collection_id}", tags=["Collections"])
async def cancel_collection(collection_id: str, user: dict = Depends(verify_token)):
    info = active_collections.get(collection_id)
    if not info:
        raise HTTPException(status_code=404, detail="Collection not found")
    if info["status"] in {"completed", "failed", "cancelled"}:
        raise HTTPException(status_code=400, detail="Collection is not running")
    active_collections[collection_id].update(status="cancelled", end_time=datetime.utcnow())
    log.info("collection_cancelled", id=collection_id, user=user["user"])
    return {"message": "Collection cancelled"}


# ---------------------------------------------------------------------------
# WebSocket — real-time progress
# ---------------------------------------------------------------------------
@app.websocket("/api/ws/collections/{collection_id}")
async def collection_ws(websocket: WebSocket, collection_id: str):
    await websocket.accept()
    try:
        while True:
            if collection_id in active_collections:
                info = active_collections[collection_id]
                await websocket.send_json(
                    {
                        "collection_id": collection_id,
                        "status":        info["status"],
                        "progress":      info.get("progress", 0),
                        "timestamp":     datetime.utcnow().isoformat(),
                    }
                )
                if info["status"] in {"completed", "failed", "cancelled"}:
                    break
            await asyncio.sleep(1)
    except Exception as exc:
        log.error("websocket_error", error=str(exc))
    finally:
        await websocket.close()


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
@app.get("/api/metrics", tags=["System"])
async def get_metrics():
    """Operational metrics — counts, statuses, uptime."""
    import platform as _platform
    try:
        import psutil as _psutil
        mem = _psutil.virtual_memory()
        mem_used_mb  = round(mem.used  / 1024 / 1024, 1)
        mem_total_mb = round(mem.total / 1024 / 1024, 1)
        cpu_percent  = _psutil.cpu_percent(interval=0.1)
    except ImportError:
        mem_used_mb = mem_total_mb = cpu_percent = None

    status_counts: Dict[str, int] = {}
    findings_total = 0
    for info in active_collections.values():
        s = info.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1
        findings_total += len(info.get("findings", []))

    return {
        "forensichunter_version": "2.0.0",
        "environment": _ENV,
        "uptime_seconds": round(time.time() - system_start_time, 1),
        "collections": {
            "total": len(active_collections),
            "by_status": status_counts,
        },
        "findings_total": findings_total,
        "system": {
            "python_version": platform.python_version(),
            "os": _platform.system(),
            "cpu_percent": cpu_percent,
            "memory_used_mb": mem_used_mb,
            "memory_total_mb": mem_total_mb,
        },
    }


# ---------------------------------------------------------------------------
# Remote analysis
# ---------------------------------------------------------------------------

class RemoteRequest(BaseModel):
    host: str
    artifact_types: List[str] = ["eventlogs", "registry", "process", "network"]
    output_dir: str = "forensichunter_report"


@app.post("/api/remote", tags=["Remote"], dependencies=[Depends(verify_token)])
async def start_remote_analysis(req: RemoteRequest):
    """Launch a forensic analysis on a remote host via an agent session."""
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    try:
        from src.remote.remote_analyzer import RemoteAnalyzer
        config = _get_config()
        ra = RemoteAnalyzer(config)
        session = ra.create_session({"host": req.host, "output_dir": req.output_dir})
        sid = session.get("session_id", session_id)
        ra.deploy_agent(sid, {})
        artifacts = ra.collect_artifacts(sid, req.artifact_types)
        analysis  = ra.analyze_artifacts(sid)
        report    = ra.generate_report(sid, format="html")
        ra.cleanup_session(sid)
        return {
            "session_id": sid,
            "host": req.host,
            "status": "completed",
            "artifact_count": len(artifacts.get("artifacts", [])),
            "report_path": report.get("report_path"),
        }
    except ImportError:
        raise HTTPException(status_code=501, detail="remote_analyzer module not available")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Cloud analysis
# ---------------------------------------------------------------------------

class CloudRequest(BaseModel):
    provider: str  # aws | azure | gcp
    options: Dict[str, str] = {}
    output_dir: str = "forensichunter_report"


@app.post("/api/cloud", tags=["Cloud"], dependencies=[Depends(verify_token)])
async def start_cloud_analysis(req: CloudRequest):
    """Launch a forensic analysis of a cloud provider environment."""
    if req.provider not in ("aws", "azure", "gcp"):
        raise HTTPException(status_code=400, detail="provider must be aws, azure, or gcp")
    try:
        from src.cloud.cloud_analyzer import CloudAnalyzer
        config = _get_config()
        ca = CloudAnalyzer(config)
        options = {**req.options, "output_dir": req.output_dir}
        results = ca.analyze(req.provider, options)
        return {
            "provider": req.provider,
            "status": "completed",
            "artifact_count": len(results.get("artifacts", [])),
            "results": results,
        }
    except ImportError:
        raise HTTPException(status_code=501, detail="cloud_analyzer module not available")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


def _get_config():
    """Return a minimal Config object for API-invoked modules."""
    class _Cfg:
        def get(self, key, default=None):
            return default
    return _Cfg()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def _startup():
    log.info("forensichunter_api_starting", env=_ENV)


@app.on_event("shutdown")
async def _shutdown():
    log.info("forensichunter_api_stopping")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

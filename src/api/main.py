"""
ForensicHunter Enterprise API
Professional REST API for enterprise forensic operations

Features:
- RESTful API for all forensic operations
- Real-time WebSocket updates
- Enterprise authentication and authorization
- SIEM integration endpoints
- Swagger/OpenAPI documentation
- Prometheus metrics
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import uuid
import time
import os
import psutil

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
import structlog

# Enterprise imports
from ..core.enterprise_config import EnterpriseConfig, ENTERPRISE_TARGETS, ENTERPRISE_MODULES
from ..core.enterprise_collector import EnterpriseCollector

# Setup structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Pydantic models
class CollectionRequest(BaseModel):
    targets: List[str] = Field(..., description="List of targets to collect")
    destination: str = Field(..., description="Destination directory")
    case_name: Optional[str] = Field(None, description="Case name for documentation")
    investigator: Optional[str] = Field(None, description="Investigator name")
    compress: bool = Field(False, description="Compress collected files")
    encrypt: bool = Field(False, description="Encrypt collected files")
    parallel_workers: Optional[int] = Field(None, description="Number of parallel workers")

class ModuleRequest(BaseModel):
    modules: List[str] = Field(..., description="List of modules to execute")
    evidence_path: str = Field(..., description="Path to evidence directory")
    timeout: int = Field(1800, description="Timeout per module in seconds")
    parallel: int = Field(1, description="Number of parallel modules")

class CollectionStatus(BaseModel):
    collection_id: str
    status: str
    progress: float
    start_time: datetime
    estimated_completion: Optional[datetime]
    files_collected: int
    bytes_collected: int
    current_target: Optional[str]
    error_message: Optional[str]

class SystemStatus(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    active_collections: int
    system_resources: Dict[str, Any]
    dependencies_status: Dict[str, bool]

class InvestigationRequest(BaseModel):
    case_name: str = Field(..., description="Case name")
    investigator: str = Field(..., description="Investigator name")
    targets: List[str] = Field(default_factory=lambda: ["all"], description="Targets to collect")
    modules: List[str] = Field(default_factory=lambda: ["all"], description="Modules to execute")
    destination: str = Field(..., description="Investigation directory")
    memory_dump: Optional[str] = Field(None, description="Path to memory dump")
    report_formats: List[str] = Field(default_factory=lambda: ["json", "html"], description="Report formats")

# Initialize FastAPI app
app = FastAPI(
    title="ForensicHunter Enterprise API",
    description="Professional Digital Forensics Platform API",
    version="2.0.0-enterprise",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Global state
config = EnterpriseConfig()
active_collections: Dict[str, Dict] = {}
system_start_time = time.time()

# Security
security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API token - implement proper JWT validation in production"""
    # TODO: Implement proper JWT token validation
    if credentials.credentials == "dev-token":
        return {"user": "admin", "permissions": ["all"]}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

# API Routes

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now()}

@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """Get comprehensive system status"""
    
    # Check dependencies
    dependencies = {}
    for dep in ["volatility3", "yara", "psutil", "fastapi"]:
        try:
            __import__(dep.replace('-', '_'))
            dependencies[dep] = True
        except ImportError:
            dependencies[dep] = False
    
    # System resources
    resources = {}
    try:
        resources = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": dict(psutil.disk_usage('/')),
            "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        }
    except Exception:
        resources = {"error": "Unable to get system resources"}
    
    return SystemStatus(
        status="operational",
        version="2.0.0-enterprise",
        uptime_seconds=time.time() - system_start_time,
        active_collections=len(active_collections),
        system_resources=resources,
        dependencies_status=dependencies
    )

@app.get("/api/targets")
async def list_targets():
    """List available forensic targets"""
    return {
        "targets": ENTERPRISE_TARGETS,
        "count": len(ENTERPRISE_TARGETS)
    }

@app.get("/api/targets/{target_name}")
async def get_target_info(target_name: str):
    """Get detailed information about a specific target"""
    if target_name not in ENTERPRISE_TARGETS:
        raise HTTPException(status_code=404, detail="Target not found")
    
    return ENTERPRISE_TARGETS[target_name]

@app.get("/api/modules")
async def list_modules():
    """List available analysis modules"""
    return {
        "modules": ENTERPRISE_MODULES,
        "count": len(ENTERPRISE_MODULES)
    }

@app.get("/api/modules/{module_name}")
async def get_module_info(module_name: str):
    """Get detailed information about a specific module"""
    if module_name not in ENTERPRISE_MODULES:
        raise HTTPException(status_code=404, detail="Module not found")
    
    return ENTERPRISE_MODULES[module_name]

@app.post("/api/collections")
async def start_collection(
    request: CollectionRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(verify_token)
):
    """Start a new forensic collection"""
    
    # Validate targets
    invalid_targets = [t for t in request.targets if t not in ENTERPRISE_TARGETS and t != "all"]
    if invalid_targets:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid targets: {', '.join(invalid_targets)}"
        )
    
    # Create collector
    collector = EnterpriseCollector(config)
    collection_id = collector.collection_id
    
    # Store collection info
    active_collections[collection_id] = {
        "id": collection_id,
        "status": "starting",
        "progress": 0.0,
        "start_time": datetime.now(),
        "request": request.dict(),
        "user": user["user"],
        "collector": collector
    }
    
    # Start collection in background
    background_tasks.add_task(
        run_collection_task,
        collection_id,
        request
    )
    
    logger.info("Collection started", collection_id=collection_id, user=user["user"])
    
    return {
        "collection_id": collection_id,
        "status": "started",
        "message": "Collection started successfully"
    }

async def run_collection_task(collection_id: str, request: CollectionRequest):
    """Background task to run collection"""
    collector = active_collections[collection_id]["collector"]
    
    try:
        active_collections[collection_id]["status"] = "collecting"
        
        # Determine targets
        targets = list(ENTERPRISE_TARGETS.keys()) if "all" in request.targets else request.targets
        
        # Progress callback
        def progress_callback(current, total):
            if collection_id in active_collections:
                active_collections[collection_id]["progress"] = (current / total) * 100
                active_collections[collection_id]["current_target"] = f"Target {current}/{total}"
        
        # Run collection
        result = await collector.collect_targets(
            target_names=targets,
            output_path=request.destination,
            progress_callback=progress_callback
        )
        
        # Update status
        active_collections[collection_id].update({
            "status": "completed",
            "progress": 100.0,
            "end_time": datetime.now(),
            "result": result,
            "files_collected": collector.stats["files_collected"],
            "bytes_collected": collector.stats["bytes_collected"]
        })
        
        logger.info("Collection completed", collection_id=collection_id)
        
    except Exception as e:
        active_collections[collection_id].update({
            "status": "failed",
            "error_message": str(e),
            "end_time": datetime.now()
        })
        
        logger.error("Collection failed", collection_id=collection_id, error=str(e))

@app.get("/api/collections")
async def list_collections(user: dict = Depends(verify_token)):
    """List all collections"""
    return {
        "collections": [
            {
                "id": col_id,
                "status": info["status"],
                "start_time": info["start_time"],
                "progress": info.get("progress", 0),
                "user": info.get("user")
            }
            for col_id, info in active_collections.items()
        ],
        "count": len(active_collections)
    }

@app.get("/api/collections/{collection_id}", response_model=CollectionStatus)
async def get_collection_status(collection_id: str, user: dict = Depends(verify_token)):
    """Get status of a specific collection"""
    if collection_id not in active_collections:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    info = active_collections[collection_id]
    
    return CollectionStatus(
        collection_id=collection_id,
        status=info["status"],
        progress=info.get("progress", 0.0),
        start_time=info["start_time"],
        estimated_completion=info.get("estimated_completion"),
        files_collected=info.get("files_collected", 0),
        bytes_collected=info.get("bytes_collected", 0),
        current_target=info.get("current_target"),
        error_message=info.get("error_message")
    )

@app.delete("/api/collections/{collection_id}")
async def cancel_collection(collection_id: str, user: dict = Depends(verify_token)):
    """Cancel a running collection"""
    if collection_id not in active_collections:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    info = active_collections[collection_id]
    
    if info["status"] in ["completed", "failed", "cancelled"]:
        raise HTTPException(status_code=400, detail="Collection is not running")
    
    # TODO: Implement proper cancellation mechanism
    active_collections[collection_id]["status"] = "cancelled"
    active_collections[collection_id]["end_time"] = datetime.now()
    
    logger.info("Collection cancelled", collection_id=collection_id, user=user["user"])
    
    return {"message": "Collection cancelled successfully"}

@app.post("/api/modules/execute")
async def execute_modules(
    request: ModuleRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(verify_token)
):
    """Execute analysis modules"""
    
    # Validate modules
    invalid_modules = [m for m in request.modules if m not in ENTERPRISE_MODULES and m != "all"]
    if invalid_modules:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid modules: {', '.join(invalid_modules)}"
        )
    
    # Create collector for module execution
    collector = EnterpriseCollector(config)
    execution_id = collector.collection_id
    
    # Store execution info
    active_collections[execution_id] = {
        "id": execution_id,
        "type": "module_execution",
        "status": "starting",
        "start_time": datetime.now(),
        "request": request.dict(),
        "user": user["user"]
    }
    
    # Start execution in background
    background_tasks.add_task(
        run_modules_task,
        execution_id,
        request,
        collector
    )
    
    logger.info("Module execution started", execution_id=execution_id, user=user["user"])
    
    return {
        "execution_id": execution_id,
        "status": "started",
        "message": "Module execution started successfully"
    }

async def run_modules_task(execution_id: str, request: ModuleRequest, collector: EnterpriseCollector):
    """Background task to run modules"""
    try:
        active_collections[execution_id]["status"] = "executing"
        
        # Determine modules
        modules = list(ENTERPRISE_MODULES.keys()) if "all" in request.modules else request.modules
        
        # Execute modules
        result = await collector.execute_modules(
            module_names=modules,
            evidence_path=request.evidence_path
        )
        
        # Update status
        active_collections[execution_id].update({
            "status": "completed",
            "end_time": datetime.now(),
            "result": result,
            "modules_executed": len(modules)
        })
        
        logger.info("Module execution completed", execution_id=execution_id)
        
    except Exception as e:
        active_collections[execution_id].update({
            "status": "failed",
            "error_message": str(e),
            "end_time": datetime.now()
        })
        
        logger.error("Module execution failed", execution_id=execution_id, error=str(e))

@app.post("/api/investigations")
async def start_investigation(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(verify_token)
):
    """Start a complete forensic investigation workflow"""
    
    collector = EnterpriseCollector(config)
    investigation_id = collector.collection_id
    
    # Store investigation info
    active_collections[investigation_id] = {
        "id": investigation_id,
        "type": "investigation",
        "status": "starting",
        "start_time": datetime.now(),
        "request": request.dict(),
        "user": user["user"],
        "collector": collector
    }
    
    # Start investigation in background
    background_tasks.add_task(
        run_investigation_task,
        investigation_id,
        request
    )
    
    logger.info("Investigation started", investigation_id=investigation_id, user=user["user"])
    
    return {
        "investigation_id": investigation_id,
        "status": "started",
        "message": "Investigation started successfully"
    }

async def run_investigation_task(investigation_id: str, request: InvestigationRequest):
    """Background task to run complete investigation"""
    collector = active_collections[investigation_id]["collector"]
    
    try:
        # Phase 1: Collection
        active_collections[investigation_id]["status"] = "collecting"
        active_collections[investigation_id]["phase"] = "collection"
        
        targets = list(ENTERPRISE_TARGETS.keys()) if "all" in request.targets else request.targets
        
        collection_result = await collector.collect_targets(
            target_names=targets,
            output_path=request.destination
        )
        
        # Phase 2: Analysis
        active_collections[investigation_id]["status"] = "analyzing"
        active_collections[investigation_id]["phase"] = "analysis"
        
        modules = list(ENTERPRISE_MODULES.keys()) if "all" in request.modules else request.modules
        
        module_results = await collector.execute_modules(
            module_names=modules,
            evidence_path=request.destination
        )
        
        # Phase 3: Reporting
        active_collections[investigation_id]["status"] = "reporting"
        active_collections[investigation_id]["phase"] = "reporting"
        
        # Generate comprehensive report
        report_data = {
            "investigation_id": investigation_id,
            "case_name": request.case_name,
            "investigator": request.investigator,
            "start_time": active_collections[investigation_id]["start_time"],
            "collection_result": collection_result,
            "module_results": module_results,
            "summary": {
                "files_collected": collector.stats["files_collected"],
                "modules_executed": collector.stats["modules_executed"],
                "total_duration": time.time() - time.mktime(active_collections[investigation_id]["start_time"].timetuple())
            }
        }
        
        # Save reports in requested formats
        import json
        from pathlib import Path
        
        investigation_dir = Path(request.destination)
        
        for fmt in request.report_formats:
            if fmt.lower() == "json":
                report_file = investigation_dir / "investigation_report.json"
                with open(report_file, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
            
            # TODO: Implement HTML and PDF report generation
        
        # Complete investigation
        active_collections[investigation_id].update({
            "status": "completed",
            "end_time": datetime.now(),
            "result": report_data,
            "phase": "completed"
        })
        
        logger.info("Investigation completed", investigation_id=investigation_id)
        
    except Exception as e:
        active_collections[investigation_id].update({
            "status": "failed",
            "error_message": str(e),
            "end_time": datetime.now()
        })
        
        logger.error("Investigation failed", investigation_id=investigation_id, error=str(e))

@app.get("/api/investigations/{investigation_id}/report")
async def download_investigation_report(
    investigation_id: str,
    format: str = "json",
    user: dict = Depends(verify_token)
):
    """Download investigation report"""
    if investigation_id not in active_collections:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    info = active_collections[investigation_id]
    
    if info["status"] != "completed":
        raise HTTPException(status_code=400, detail="Investigation not completed")
    
    # TODO: Implement report file serving
    return {"message": "Report download not yet implemented"}

@app.websocket("/api/ws/collections/{collection_id}")
async def collection_websocket(websocket: WebSocket, collection_id: str):
    """WebSocket endpoint for real-time collection updates"""
    await websocket.accept()
    
    try:
        while True:
            if collection_id in active_collections:
                status_data = {
                    "collection_id": collection_id,
                    "status": active_collections[collection_id]["status"],
                    "progress": active_collections[collection_id].get("progress", 0),
                    "timestamp": datetime.now().isoformat()
                }
                
                await websocket.send_json(status_data)
                
                # Stop sending if collection is finished
                if active_collections[collection_id]["status"] in ["completed", "failed", "cancelled"]:
                    break
            
            await asyncio.sleep(1)  # Update every second
            
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
    finally:
        await websocket.close()

@app.get("/api/metrics")
async def get_metrics():
    """Get system metrics in Prometheus format"""
    # TODO: Implement proper Prometheus metrics
    return {
        "active_collections": len(active_collections),
        "system_uptime": time.time() - system_start_time,
        "total_collections": len(active_collections)  # This should be from persistent storage
    }

# SIEM Integration endpoints
@app.post("/api/siem/events")
async def send_siem_event(event_data: Dict[str, Any], user: dict = Depends(verify_token)):
    """Send forensic event to SIEM system"""
    # TODO: Implement SIEM integration
    logger.info("SIEM event", event_data=event_data, user=user["user"])
    return {"message": "Event sent to SIEM (not implemented)"}

@app.get("/api/siem/status")
async def get_siem_status():
    """Get SIEM integration status"""
    return {
        "siem_enabled": config.get("logging.siem_enabled", False),
        "siem_endpoint": config.get("logging.siem_endpoint", ""),
        "last_event": None  # TODO: Track last SIEM event
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    logger.info("ForensicHunter Enterprise API starting up")
    
    # TODO: Initialize database connections
    # TODO: Load existing collections from database
    # TODO: Start background cleanup tasks

# Shutdown event  
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info("ForensicHunter Enterprise API shutting down")
    
    # TODO: Save active collections to database
    # TODO: Clean up resources

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
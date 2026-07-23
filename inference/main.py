"""
inference/main.py  (PostgreSQL edition)
========================================
FastAPI application — fully wired to PostgreSQL via the db/ layer.

Changes from previous version:
  - Hardcoded users removed → users table
  - localStorage incidents removed → incidents table
  - Every scan persisted to scans table
  - Every privileged action written to audit_log
  - /incidents CRUD endpoints added
  - /model-versions endpoint added (for rollback UI)
  - Lifespan startup/shutdown manages DB pool

No other logic changed (prediction, hardening, JWT) so existing
tests continue to pass.
"""
import asyncio
import hashlib
from core.monitoring import run_health_monitor, alert_db_down, alert_model_load_failed
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from db import (
    AuditRepository,
    HardeningRoundRepository,
    IncidentRepository,
    ModelVersionRepository,
    ScanRepository,
    UserRepository,
    db,
)
from db.models import (
    AuditEntry,
    Comment,
    CommentCreate,
    Incident,
    IncidentCreate,
    IncidentSummary,
    IncidentUpdate,
    ModelVersion,
    PaginatedResponse,
    Scan,
    ScanCreate,
    ScanSummary,
    User,
)
from inference.auth import (
    Token,
    create_access_token,
    get_current_user,
)
from inference.model_loader import get_model_loader

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("navigo.api")


# ── Rate limiting ───────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])


# ── Lifespan ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    monitor_task = asyncio.create_task(run_health_monitor(300))
    yield
    # Shutdown
    monitor_task.cancel()
    await db.disconnect()


# ── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Navigo Adversarial Defense API",
    version="2.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Tighten to your domain in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Repositories (dependency injection) ─────────────────────────────────────

def get_users():
    return UserRepository(db)

def get_scans():
    return ScanRepository(db)

def get_incidents():
    return IncidentRepository(db)

def get_audit():
    return AuditRepository(db)

def get_model_versions():
    return ModelVersionRepository(db)

def get_hardening():
    return HardeningRoundRepository(db)


# ============================================================
# AUTH ENDPOINTS
# ============================================================

from fastapi.security import OAuth2PasswordRequestForm

@app.post("/token", response_model=Token, tags=["Auth"])
@limiter.limit("10/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    users: UserRepository = Depends(get_users),
    audit: AuditRepository = Depends(get_audit),
):
    user = await users.verify_password(form_data.username, form_data.password)
    if not user:
        await audit.log(
            action="auth.login.failed",
            actor_name=form_data.username,
            ip_address=request.client.host,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await users.touch_last_login(user["id"])
    await audit.log(
        action="auth.login.success",
        actor_id=user["id"],
        actor_name=user["username"],
        ip_address=request.client.host,
    )

    token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    return {"access_token": token, "token_type": "bearer"}


# ============================================================
# HEALTH
# ============================================================

@app.get("/health", tags=["System"])
async def health(scans: ScanRepository = Depends(get_scans)):
    loader = get_model_loader()
    stats = await scans.stats_last_24h()
    return {
        "status": "ok",
        "models_ready": loader.is_ready(),
        "scans_last_24h": stats,
    }


# ============================================================
# PREDICTION — feature vector
# ============================================================

@app.post("/predict", tags=["Detection"])
@limiter.limit("60/minute")
async def predict(
    request: Request,
    payload: dict,
    current_user: dict = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scans),
    audit: AuditRepository = Depends(get_audit),
):
    features = payload.get("features")
    if not features or len(features) != 522:
        raise HTTPException(400, "Expected 522-dimensional feature vector")

    t0 = time.perf_counter()
    loader = get_model_loader()
    result = loader.predict(features)
    latency_ms = int((time.perf_counter() - t0) * 1000)

    risk = max(0.0, result["risk_score"])
    verdict = _risk_to_verdict(risk)

    scan = await scans.create(ScanCreate(
        scan_type="vector",
        malware_prob=result["malware_prob"],
        suspicion_score=result["suspicion_score"],
        risk_score=risk,
        verdict=verdict,
        scanned_by=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
        model_version=loader.version_tag,
        processing_ms=latency_ms,
        ip_address=request.client.host,
    ))

    await audit.log(
        action="scan.predict",
        actor_id=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
        actor_name=current_user.get("username"),
        resource=f"scan:{scan.id}",
        detail={"verdict": verdict, "risk_score": risk},
        ip_address=request.client.host,
    )

    return {
        "scan_id": str(scan.id),
        "malware_prob": result["malware_prob"],
        "suspicion_score": result["suspicion_score"],
        "risk_score": risk,
        "verdict": verdict,
        "latency_ms": latency_ms,
    }


# ============================================================
# SCAN FILE — upload PE executable
# ============================================================

@app.post("/scan-file", tags=["Detection"])
@limiter.limit("20/minute")
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scans),
    audit: AuditRepository = Depends(get_audit),
):
    MAX_BYTES = 50 * 1024 * 1024  # 50 MB
    contents = await file.read(MAX_BYTES + 1)
    if len(contents) > MAX_BYTES:
        raise HTTPException(413, "File exceeds 50 MB limit")

    file_hash = hashlib.sha256(contents).hexdigest()

    # Check if we've seen this file before (log it but still create new scan)
    existing = await scans.get_by_hash(file_hash)
    if existing:
        logger.info("Previously seen file hash %s — creating new scan record", file_hash[:16])

    t0 = time.perf_counter()
    loader = get_model_loader()

    try:
        features = loader.extract_pe_features(contents)
    except Exception as exc:
        raise HTTPException(422, f"PE feature extraction failed: {exc}")

    result = loader.predict(features)
    latency_ms = int((time.perf_counter() - t0) * 1000)

    risk = max(0.0, result["risk_score"])
    verdict = _risk_to_verdict(risk)

    scan = await scans.create(ScanCreate(
        scan_type="file",
        filename=file.filename,
        file_hash_sha256=file_hash,
        file_size_bytes=len(contents),
        malware_prob=result["malware_prob"],
        suspicion_score=result["suspicion_score"],
        risk_score=risk,
        verdict=verdict,
        scanned_by=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
        model_version=loader.version_tag,
        processing_ms=latency_ms,
        ip_address=request.client.host,
    ))

    await audit.log(
        action="scan.file",
        actor_id=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
        actor_name=current_user.get("username"),
        resource=f"scan:{scan.id}",
        detail={"filename": file.filename, "verdict": verdict, "hash": file_hash[:16]},
        ip_address=request.client.host,
    )

    # Auto-create incident for malicious files
    if verdict == "malicious":
        incidents = IncidentRepository(db)
        await incidents.create(IncidentCreate(
            scan_id=scan.id,
            title=f"Malicious file detected: {file.filename}",
            description=f"Risk score {risk:.2f} — auto-escalated by scanner.",
            severity="high" if risk < 0.9 else "critical",
            created_by=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
            tags=["auto-escalated", "file-scan"],
        ))

    return {
        "scan_id": str(scan.id),
        "cached": False,
        "filename": file.filename,
        "file_hash": file_hash,
        "malware_prob": result["malware_prob"],
        "suspicion_score": result["suspicion_score"],
        "risk_score": risk,
        "verdict": verdict,
        "latency_ms": latency_ms,
    }


# ============================================================
# TRAINING REPORT
# ============================================================

@app.get("/training-report", tags=["System"])
async def training_report(current_user: dict = Depends(get_current_user)):
    """Returns real training metrics from logs/training_log.json."""
    import json, pathlib
    log_path = pathlib.Path("logs/training_log.json")
    if not log_path.exists():
        raise HTTPException(404, "Training log not found")
    return json.loads(log_path.read_text())


# ============================================================
# SCANS — list & detail
# ============================================================

@app.get("/scans", response_model=PaginatedResponse, tags=["Scans"])
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    verdict: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scans),
):
    offset = (page - 1) * page_size
    items = await scans.list_recent(limit=page_size, offset=offset, verdict=verdict)
    total = await scans.count(verdict=verdict)
    return PaginatedResponse(total=total, page=page, page_size=page_size, items=items)


@app.get("/scans/{scan_id}", response_model=Scan, tags=["Scans"])
async def get_scan(
    scan_id: uuid.UUID,
    current_user: dict = Depends(get_current_user),
    scans: ScanRepository = Depends(get_scans),
):
    scan = await scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


# ============================================================
# INCIDENTS — full CRUD
# ============================================================

@app.get("/incidents", response_model=PaginatedResponse, tags=["Incidents"])
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    incidents: IncidentRepository = Depends(get_incidents),
):
    offset = (page - 1) * page_size
    items = await incidents.list_incidents(
        limit=page_size, offset=offset,
        status=status, severity=severity, search=search,
    )
    total = await incidents.count(status=status, severity=severity)
    return PaginatedResponse(total=total, page=page, page_size=page_size, items=items)


@app.post("/incidents", response_model=Incident, status_code=201, tags=["Incidents"])
async def create_incident(
    request: Request,
    data: IncidentCreate,
    current_user: dict = Depends(get_current_user),
    incidents: IncidentRepository = Depends(get_incidents),
    audit: AuditRepository = Depends(get_audit),
):
    data.created_by = uuid.UUID(current_user["id"]) if current_user.get("id") else None
    incident = await incidents.create(data)
    await audit.log(
        action="incident.create",
        actor_id=data.created_by,
        actor_name=current_user.get("username"),
        resource=f"incident:{incident.id}",
        detail={"title": incident.title, "severity": incident.severity},
        ip_address=request.client.host,
    )
    return incident


@app.get("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
async def get_incident(
    incident_id: uuid.UUID,
    current_user: dict = Depends(get_current_user),
    incidents: IncidentRepository = Depends(get_incidents),
):
    incident = await incidents.get(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@app.patch("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
async def update_incident(
    request: Request,
    incident_id: uuid.UUID,
    data: IncidentUpdate,
    current_user: dict = Depends(get_current_user),
    incidents: IncidentRepository = Depends(get_incidents),
    audit: AuditRepository = Depends(get_audit),
):
    incident = await incidents.update(incident_id, data)
    if not incident:
        raise HTTPException(404, "Incident not found")
    await audit.log(
        action="incident.update",
        actor_id=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
        actor_name=current_user.get("username"),
        resource=f"incident:{incident_id}",
        detail=data.model_dump(exclude_none=True),
        ip_address=request.client.host,
    )
    return incident


@app.get("/incidents/{incident_id}/comments", response_model=List[Comment], tags=["Incidents"])
async def get_comments(
    incident_id: uuid.UUID,
    current_user: dict = Depends(get_current_user),
    incidents: IncidentRepository = Depends(get_incidents),
):
    return await incidents.get_comments(incident_id)


@app.post("/incidents/{incident_id}/comments", response_model=Comment, status_code=201, tags=["Incidents"])
async def add_comment(
    request: Request,
    incident_id: uuid.UUID,
    body: dict,
    current_user: dict = Depends(get_current_user),
    incidents: IncidentRepository = Depends(get_incidents),
):
    data = CommentCreate(
        incident_id=incident_id,
        author_id=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
        body=body.get("body", ""),
    )
    return await incidents.add_comment(data)


# ============================================================
# MODEL VERSIONS
# ============================================================

@app.get("/model-versions", response_model=List[ModelVersion], tags=["Models"])
async def list_model_versions(
    model_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    versions: ModelVersionRepository = Depends(get_model_versions),
):
    _require_admin(current_user)
    return await versions.list_versions(model_type=model_type)


@app.post("/model-versions/{version_id}/activate", tags=["Models"])
async def activate_model_version(
    request: Request,
    version_id: uuid.UUID,
    current_user: dict = Depends(get_current_user),
    versions: ModelVersionRepository = Depends(get_model_versions),
    audit: AuditRepository = Depends(get_audit),
):
    _require_admin(current_user)
    ver = await versions.list_versions()
    target = next((v for v in ver if v.id == version_id), None)
    if not target:
        raise HTTPException(404, "Model version not found")
    await versions.activate(version_id, target.model_type)
    await audit.log(
        action="model.activate",
        actor_id=uuid.UUID(current_user["id"]) if current_user.get("id") else None,
        actor_name=current_user.get("username"),
        resource=f"model_version:{version_id}",
        detail={"version_tag": target.version_tag, "model_type": target.model_type},
        ip_address=request.client.host,
    )
    return {"status": "activated", "version_tag": target.version_tag}


# ============================================================
# AUDIT LOG (admin only)
# ============================================================

@app.get("/audit-log", response_model=List[AuditEntry], tags=["System"])
async def get_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
    audit: AuditRepository = Depends(get_audit),
):
    _require_admin(current_user)
    return await audit.recent(limit=limit)


# ============================================================
# STATIC FILES (frontend)
# ============================================================

app.mount("/", StaticFiles(directory="app", html=True), name="frontend")


# ============================================================
# HELPERS
# ============================================================

def _risk_to_verdict(risk: float) -> str:
    if risk >= 0.7:
        return "malicious"
    if risk >= 0.4:
        return "suspicious"
    return "clean"


def _require_admin(user: dict) -> None:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
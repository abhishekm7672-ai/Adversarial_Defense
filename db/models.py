"""
db/models.py
============
Pydantic schemas for every database entity.

Naming convention:
  <Entity>            — full DB record (includes id, timestamps)
  <Entity>Create      — fields needed to INSERT a new record
  <Entity>Update      — optional fields for PATCH operations
  <Entity>Summary     — lightweight version for list endpoints
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------

class NavigoBase(BaseModel):
    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------

class UserCreate(NavigoBase):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=10)
    role: str = Field("analyst")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        allowed = {"admin", "analyst", "readonly"}
        if v not in allowed:
            raise ValueError(f"role must be one of {allowed}")
        return v


class User(NavigoBase):
    id: uuid.UUID
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class UserSummary(NavigoBase):
    id: uuid.UUID
    username: str
    role: str


# ---------------------------------------------------------------------------
# SCANS
# ---------------------------------------------------------------------------

class ScanCreate(NavigoBase):
    scan_type: str
    filename: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    malware_prob: float
    suspicion_score: float
    risk_score: float
    verdict: str
    scanned_by: Optional[uuid.UUID] = None
    model_version: Optional[str] = None
    processing_ms: Optional[int] = None
    ip_address: Optional[Any] = None
    notes: Optional[str] = None

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        allowed = {"clean", "suspicious", "malicious"}
        if v not in allowed:
            raise ValueError(f"verdict must be one of {allowed}")
        return v


class Scan(NavigoBase):
    id: uuid.UUID
    scan_type: str
    filename: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    malware_prob: float
    suspicion_score: float
    risk_score: float
    verdict: str
    scanned_by: Optional[uuid.UUID] = None
    scanned_at: datetime
    model_version: Optional[str] = None
    processing_ms: Optional[int] = None
    ip_address: Optional[Any] = None
    notes: Optional[str] = None


class ScanSummary(NavigoBase):
    id: uuid.UUID
    scan_type: str
    filename: Optional[str] = None
    risk_score: float
    verdict: str
    scanned_at: datetime


# ---------------------------------------------------------------------------
# INCIDENTS
# ---------------------------------------------------------------------------

class IncidentCreate(NavigoBase):
    scan_id: Optional[uuid.UUID] = None
    title: str = Field(..., min_length=3, max_length=256)
    description: Optional[str] = None
    severity: str
    assigned_to: Optional[uuid.UUID] = None
    created_by: Optional[uuid.UUID] = None
    siem_ref: Optional[str] = None
    tags: Optional[List[str]] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v


class IncidentUpdate(NavigoBase):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None
    siem_ref: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"open", "investigating", "resolved", "false_positive"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}")
        return v


class Incident(NavigoBase):
    id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assigned_to: Optional[uuid.UUID] = None
    created_by: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    siem_ref: Optional[str] = None
    tags: Optional[List[str]] = None


class IncidentSummary(NavigoBase):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    created_at: datetime


# ---------------------------------------------------------------------------
# INCIDENT COMMENTS
# ---------------------------------------------------------------------------

class CommentCreate(NavigoBase):
    incident_id: uuid.UUID
    author_id: Optional[uuid.UUID] = None
    body: str = Field(..., min_length=1)


class Comment(NavigoBase):
    id: uuid.UUID
    incident_id: uuid.UUID
    author_id: Optional[uuid.UUID] = None
    body: str
    created_at: datetime


# ---------------------------------------------------------------------------
# MODEL VERSIONS
# ---------------------------------------------------------------------------

class ModelVersionCreate(NavigoBase):
    version_tag: str
    model_type: str
    file_path: str
    file_size_bytes: Optional[int] = None
    checksum_sha256: Optional[str] = None
    ember_samples: Optional[int] = None
    val_auc: Optional[float] = None
    val_accuracy: Optional[float] = None
    evasion_rate: Optional[float] = None
    antifragility_index: Optional[float] = None
    notes: Optional[str] = None


class ModelVersion(NavigoBase):
    id: uuid.UUID
    version_tag: str
    model_type: str
    file_path: str
    file_size_bytes: Optional[int] = None
    checksum_sha256: Optional[str] = None
    trained_at: datetime
    trained_by: Optional[uuid.UUID] = None
    ember_samples: Optional[int] = None
    val_auc: Optional[float] = None
    val_accuracy: Optional[float] = None
    evasion_rate: Optional[float] = None
    antifragility_index: Optional[float] = None
    is_active: bool
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# HARDENING ROUNDS
# ---------------------------------------------------------------------------

class HardeningRoundCreate(NavigoBase):
    round_number: int
    model_version_id: Optional[uuid.UUID] = None
    evasive_samples: Optional[int] = None
    removed_poisoned: Optional[int] = None
    evasion_rate_before: Optional[float] = None
    evasion_rate_after: Optional[float] = None
    antifragility_index: Optional[float] = None
    duration_seconds: Optional[int] = None
    notes: Optional[str] = None


class HardeningRound(NavigoBase):
    id: uuid.UUID
    round_number: int
    model_version_id: Optional[uuid.UUID] = None
    evasive_samples: Optional[int] = None
    removed_poisoned: Optional[int] = None
    evasion_rate_before: Optional[float] = None
    evasion_rate_after: Optional[float] = None
    antifragility_index: Optional[float] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------

class AuditEntry(NavigoBase):
    id: int
    actor_id: Optional[uuid.UUID] = None
    actor_name: Optional[str] = None
    action: str
    resource: Optional[str] = None
    detail: Optional[Dict[str, Any]] = None
    ip_address: Optional[Any] = None
    created_at: datetime


# ---------------------------------------------------------------------------
# API RESPONSES (pagination wrapper)
# ---------------------------------------------------------------------------

class PaginatedResponse(NavigoBase):
    total: int
    page: int
    page_size: int
    items: List[Any]
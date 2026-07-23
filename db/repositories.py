"""
db/repositories.py
==================
Repository layer — all SQL queries live here, not in endpoints.

Pattern: each entity gets a Repository class with async methods.
Endpoints import the repository, not the DB directly.

Import example:
    from db.repositories import ScanRepository, IncidentRepository
    from db.database import db

    scans = ScanRepository(db)
    result = await scans.create(scan_data, user_id=current_user.id)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from passlib.hash import sha256_crypt

from db.database import Database
from db.models import (
    AuditEntry,
    Comment,
    CommentCreate,
    HardeningRound,
    HardeningRoundCreate,
    Incident,
    IncidentCreate,
    IncidentSummary,
    IncidentUpdate,
    ModelVersion,
    ModelVersionCreate,
    Scan,
    ScanCreate,
    ScanSummary,
    User,
    UserCreate,
    UserSummary,
)


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _verdict_from_score(risk_score: float) -> str:
    if risk_score >= 0.7:
        return "malicious"
    if risk_score >= 0.4:
        return "suspicious"
    return "clean"


def _row_to_dict(row) -> Dict[str, Any]:
    """Convert asyncpg Record to plain dict."""
    return dict(row) if row else {}


# ---------------------------------------------------------------------------
# USER REPOSITORY
# ---------------------------------------------------------------------------

class UserRepository:

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(self, data: UserCreate) -> User:
        pw_hash = sha256_crypt.hash(data.password)
        row = await self._db.fetchrow(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES ($1, $2, $3)
            RETURNING id, username, role, is_active, created_at, last_login
            """,
            data.username, pw_hash, data.role,
        )
        return User(**_row_to_dict(row))

    async def get_by_username(self, username: str) -> Optional[Dict]:
        """Returns full row including password_hash (used by auth only)."""
        row = await self._db.fetchrow(
            "SELECT * FROM users WHERE username = $1 AND is_active = TRUE",
            username,
        )
        return _row_to_dict(row) if row else None

    async def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        row = await self._db.fetchrow(
            """
            SELECT id, username, role, is_active, created_at, last_login
            FROM users WHERE id = $1
            """,
            user_id,
        )
        return User(**_row_to_dict(row)) if row else None

    async def touch_last_login(self, user_id: uuid.UUID) -> None:
        await self._db.execute(
            "UPDATE users SET last_login = NOW() WHERE id = $1",
            user_id,
        )

    async def list_all(self) -> List[UserSummary]:
        rows = await self._db.fetch(
            "SELECT id, username, role FROM users WHERE is_active = TRUE ORDER BY username"
        )
        return [UserSummary(**_row_to_dict(r)) for r in rows]

    async def set_active(self, user_id: uuid.UUID, active: bool) -> None:
        await self._db.execute(
            "UPDATE users SET is_active = $2 WHERE id = $1",
            user_id, active,
        )

    async def verify_password(self, username: str, password: str) -> Optional[Dict]:
        """Returns user dict if credentials valid, else None."""
        row = await self.get_by_username(username)
        if not row:
            return None
        if sha256_crypt.verify(password, row["password_hash"]):
            return row
        return None


# ---------------------------------------------------------------------------
# SCAN REPOSITORY
# ---------------------------------------------------------------------------

class ScanRepository:

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(self, data: ScanCreate) -> Scan:
        row = await self._db.fetchrow(
            """
            INSERT INTO scans (
                scan_type, filename, file_hash_sha256, file_size_bytes,
                malware_prob, suspicion_score, risk_score, verdict,
                scanned_by, model_version, processing_ms, ip_address, notes
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7, $8,
                $9, $10, $11, $12::INET, $13
            )
            RETURNING *
            """,
            data.scan_type, data.filename, data.file_hash_sha256, data.file_size_bytes,
            data.malware_prob, data.suspicion_score, data.risk_score, data.verdict,
            data.scanned_by, data.model_version, data.processing_ms,
            data.ip_address, data.notes,
        )
        return Scan(**_row_to_dict(row))

    async def get(self, scan_id: uuid.UUID) -> Optional[Scan]:
        row = await self._db.fetchrow(
            "SELECT * FROM scans WHERE id = $1", scan_id
        )
        return Scan(**_row_to_dict(row)) if row else None

    async def list_recent(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> List[ScanSummary]:
        conditions = ["1=1"]
        params: list = []
        idx = 1

        if verdict:
            conditions.append(f"verdict = ${idx}")
            params.append(verdict)
            idx += 1

        if user_id:
            conditions.append(f"scanned_by = ${idx}")
            params.append(user_id)
            idx += 1

        where = " AND ".join(conditions)
        params += [limit, offset]

        rows = await self._db.fetch(
            f"""
            SELECT id, scan_type, filename, risk_score, verdict, scanned_at
            FROM scans
            WHERE {where}
            ORDER BY scanned_at DESC
            LIMIT ${idx} OFFSET ${idx+1}
            """,
            *params,
        )
        return [ScanSummary(**_row_to_dict(r)) for r in rows]

    async def count(self, verdict: Optional[str] = None) -> int:
        if verdict:
            return await self._db.fetchval(
                "SELECT COUNT(*) FROM scans WHERE verdict = $1", verdict
            )
        return await self._db.fetchval("SELECT COUNT(*) FROM scans")

    async def stats_last_24h(self) -> Dict[str, Any]:
        """Quick stats for the dashboard health card."""
        row = await self._db.fetchrow(
            """
            SELECT
                COUNT(*)                                        AS total,
                COUNT(*) FILTER (WHERE verdict = 'malicious')  AS malicious,
                COUNT(*) FILTER (WHERE verdict = 'suspicious') AS suspicious,
                COUNT(*) FILTER (WHERE verdict = 'clean')      AS clean,
                AVG(risk_score)                                 AS avg_risk,
                AVG(processing_ms)                              AS avg_latency_ms
            FROM scans
            WHERE scanned_at >= NOW() - INTERVAL '24 hours'
            """
        )
        return _row_to_dict(row)

    async def get_by_hash(self, sha256: str) -> Optional[Scan]:
        """Lookup previous scan of same file (dedup / cache)."""
        row = await self._db.fetchrow(
            """
            SELECT * FROM scans
            WHERE file_hash_sha256 = $1
            ORDER BY scanned_at DESC LIMIT 1
            """,
            sha256,
        )
        return Scan(**_row_to_dict(row)) if row else None


# ---------------------------------------------------------------------------
# INCIDENT REPOSITORY
# ---------------------------------------------------------------------------

class IncidentRepository:

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(self, data: IncidentCreate) -> Incident:
        row = await self._db.fetchrow(
            """
            INSERT INTO incidents (
                scan_id, title, description, severity,
                assigned_to, created_by, siem_ref, tags
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7, $8
            )
            RETURNING *
            """,
            data.scan_id, data.title, data.description, data.severity,
            data.assigned_to, data.created_by, data.siem_ref,
            data.tags or [],
        )
        return Incident(**_row_to_dict(row))

    async def get(self, incident_id: uuid.UUID) -> Optional[Incident]:
        row = await self._db.fetchrow(
            "SELECT * FROM incidents WHERE id = $1", incident_id
        )
        return Incident(**_row_to_dict(row)) if row else None

    async def update(
        self, incident_id: uuid.UUID, data: IncidentUpdate
    ) -> Optional[Incident]:
        fields = data.model_dump(exclude_none=True)
        if not fields:
            return await self.get(incident_id)

        set_parts = []
        params = []
        for i, (key, val) in enumerate(fields.items(), start=1):
            set_parts.append(f"{key} = ${i}")
            params.append(val)

        if "status" in fields and fields["status"] == "resolved":
            set_parts.append("resolved_at = NOW()")

        params.append(incident_id)
        set_clause = ", ".join(set_parts)

        row = await self._db.fetchrow(
            f"""
            UPDATE incidents SET {set_clause}
            WHERE id = ${len(params)}
            RETURNING *
            """,
            *params,
        )
        return Incident(**_row_to_dict(row)) if row else None

    async def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[uuid.UUID] = None,
        search: Optional[str] = None,
    ) -> List[IncidentSummary]:
        conditions = ["1=1"]
        params: list = []
        idx = 1

        if status:
            conditions.append(f"status = ${idx}")
            params.append(status); idx += 1

        if severity:
            conditions.append(f"severity = ${idx}")
            params.append(severity); idx += 1

        if assigned_to:
            conditions.append(f"assigned_to = ${idx}")
            params.append(assigned_to); idx += 1

        if search:
            conditions.append(f"(title ILIKE ${idx} OR description ILIKE ${idx})")
            params.append(f"%{search}%"); idx += 1

        where = " AND ".join(conditions)
        params += [limit, offset]

        rows = await self._db.fetch(
            f"""
            SELECT id, title, severity, status, created_at
            FROM incidents
            WHERE {where}
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                END,
                created_at DESC
            LIMIT ${idx} OFFSET ${idx+1}
            """,
            *params,
        )
        return [IncidentSummary(**_row_to_dict(r)) for r in rows]

    async def count(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        if status and severity:
            return await self._db.fetchval(
                "SELECT COUNT(*) FROM incidents WHERE status=$1 AND severity=$2",
                status, severity,
            )
        if status:
            return await self._db.fetchval(
                "SELECT COUNT(*) FROM incidents WHERE status=$1", status
            )
        if severity:
            return await self._db.fetchval(
                "SELECT COUNT(*) FROM incidents WHERE severity=$1", severity
            )
        return await self._db.fetchval("SELECT COUNT(*) FROM incidents")

    async def add_comment(self, data: CommentCreate) -> Comment:
        row = await self._db.fetchrow(
            """
            INSERT INTO incident_comments (incident_id, author_id, body)
            VALUES ($1, $2, $3)
            RETURNING *
            """,
            data.incident_id, data.author_id, data.body,
        )
        return Comment(**_row_to_dict(row))

    async def get_comments(self, incident_id: uuid.UUID) -> List[Comment]:
        rows = await self._db.fetch(
            """
            SELECT * FROM incident_comments
            WHERE incident_id = $1
            ORDER BY created_at ASC
            """,
            incident_id,
        )
        return [Comment(**_row_to_dict(r)) for r in rows]


# ---------------------------------------------------------------------------
# MODEL VERSION REPOSITORY
# ---------------------------------------------------------------------------

class ModelVersionRepository:

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(
        self, data: ModelVersionCreate, trained_by: Optional[uuid.UUID] = None
    ) -> ModelVersion:
        row = await self._db.fetchrow(
            """
            INSERT INTO model_versions (
                version_tag, model_type, file_path, file_size_bytes,
                checksum_sha256, trained_by, ember_samples,
                val_auc, val_accuracy, evasion_rate, antifragility_index, notes
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7,
                $8, $9, $10, $11, $12
            )
            RETURNING *
            """,
            data.version_tag, data.model_type, data.file_path, data.file_size_bytes,
            data.checksum_sha256, trained_by, data.ember_samples,
            data.val_auc, data.val_accuracy, data.evasion_rate,
            data.antifragility_index, data.notes,
        )
        return ModelVersion(**_row_to_dict(row))

    async def get_active(self, model_type: str) -> Optional[ModelVersion]:
        row = await self._db.fetchrow(
            """
            SELECT * FROM model_versions
            WHERE model_type = $1 AND is_active = TRUE
            ORDER BY trained_at DESC LIMIT 1
            """,
            model_type,
        )
        return ModelVersion(**_row_to_dict(row)) if row else None

    async def activate(self, version_id: uuid.UUID, model_type: str) -> None:
        """Atomically switch active flag to a new version."""
        await self._db.execute(
            "UPDATE model_versions SET is_active = FALSE WHERE model_type = $1",
            model_type,
        )
        await self._db.execute(
            "UPDATE model_versions SET is_active = TRUE WHERE id = $1",
            version_id,
        )

    async def list_versions(self, model_type: Optional[str] = None) -> List[ModelVersion]:
        if model_type:
            rows = await self._db.fetch(
                "SELECT * FROM model_versions WHERE model_type = $1 ORDER BY trained_at DESC",
                model_type,
            )
        else:
            rows = await self._db.fetch(
                "SELECT * FROM model_versions ORDER BY trained_at DESC"
            )
        return [ModelVersion(**_row_to_dict(r)) for r in rows]


# ---------------------------------------------------------------------------
# HARDENING ROUND REPOSITORY
# ---------------------------------------------------------------------------

class HardeningRoundRepository:

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(self, data: HardeningRoundCreate) -> HardeningRound:
        row = await self._db.fetchrow(
            """
            INSERT INTO hardening_rounds (
                round_number, model_version_id, evasive_samples,
                removed_poisoned, evasion_rate_before, evasion_rate_after,
                antifragility_index, duration_seconds, notes
            ) VALUES (
                $1, $2, $3,
                $4, $5, $6,
                $7, $8, $9
            )
            RETURNING *
            """,
            data.round_number, data.model_version_id, data.evasive_samples,
            data.removed_poisoned, data.evasion_rate_before, data.evasion_rate_after,
            data.antifragility_index, data.duration_seconds, data.notes,
        )
        return HardeningRound(**_row_to_dict(row))

    async def complete_round(
        self, round_id: uuid.UUID, evasion_rate_after: float, antifragility_index: float
    ) -> None:
        await self._db.execute(
            """
            UPDATE hardening_rounds
            SET evasion_rate_after = $2,
                antifragility_index = $3,
                completed_at = NOW()
            WHERE id = $1
            """,
            round_id, evasion_rate_after, antifragility_index,
        )

    async def list_all(self) -> List[HardeningRound]:
        rows = await self._db.fetch(
            "SELECT * FROM hardening_rounds ORDER BY round_number ASC"
        )
        return [HardeningRound(**_row_to_dict(r)) for r in rows]


# ---------------------------------------------------------------------------
# AUDIT LOG REPOSITORY
# ---------------------------------------------------------------------------

class AuditRepository:

    def __init__(self, db: Database) -> None:
        self._db = db

    async def log(
        self,
        action: str,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: Optional[str] = None,
        resource: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Fire-and-forget audit insert. Errors are logged, never raised."""
        try:
            await self._db.execute(
                """
                INSERT INTO audit_log (actor_id, actor_name, action, resource, detail, ip_address)
                VALUES ($1, $2, $3, $4, $5::JSONB, $6::INET)
                """,
                actor_id, actor_name, action, resource,
                json.dumps(detail) if detail else None,
                ip_address,
            )
        except Exception as exc:
            import logging
            logging.getLogger("navigo.audit").error("Audit log insert failed: %s", exc)

    async def recent(self, limit: int = 100, actor_id: Optional[uuid.UUID] = None) -> List[AuditEntry]:
        if actor_id:
            rows = await self._db.fetch(
                "SELECT * FROM audit_log WHERE actor_id=$1 ORDER BY created_at DESC LIMIT $2",
                actor_id, limit,
            )
        else:
            rows = await self._db.fetch(
                "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1", limit
            )
        return [AuditEntry(**_row_to_dict(r)) for r in rows]
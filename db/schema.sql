-- ============================================================
-- NAVIGO ADVERSARIAL DEFENSE — PostgreSQL Schema
-- Version: 1.0.0
-- Apply with: psql -U navigo -d navigo_db -f schema.sql
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- USERS TABLE
-- Replaces hardcoded users in auth.py
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(64) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,         -- sha256_crypt hash
    role        VARCHAR(32) NOT NULL CHECK (role IN ('admin', 'analyst', 'readonly')),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

-- ============================================================
-- SCANS TABLE
-- Every file scan and feature-vector scan is recorded here
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type       VARCHAR(16) NOT NULL CHECK (scan_type IN ('file', 'vector')),
    filename        VARCHAR(512),                -- NULL for vector scans
    file_hash_sha256 CHAR(64),                   -- SHA-256 of uploaded file
    file_size_bytes BIGINT,

    -- Risk scores
    malware_prob    FLOAT NOT NULL,              -- LightGBM probability [0,1]
    suspicion_score FLOAT NOT NULL,              -- IsolationForest score [0,1]
    risk_score      FLOAT NOT NULL,              -- Fused: 0.7×malware + 0.3×suspicion
    verdict         VARCHAR(16) NOT NULL CHECK (verdict IN ('clean', 'suspicious', 'malicious')),

    -- Metadata
    scanned_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    model_version   VARCHAR(64),                 -- e.g. "lgb_v2_20260314"
    processing_ms   INTEGER,                     -- inference latency in milliseconds
    ip_address      INET,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans (scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans (verdict);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_by ON scans (scanned_by);
CREATE INDEX IF NOT EXISTS idx_scans_file_hash ON scans (file_hash_sha256);

-- ============================================================
-- INCIDENTS TABLE
-- High-severity events that analysts triage
-- ============================================================
CREATE TABLE IF NOT EXISTS incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
    title           VARCHAR(256) NOT NULL,
    description     TEXT,
    severity        VARCHAR(16) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status          VARCHAR(16) NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),

    -- Assignment
    assigned_to     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Timeline
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,

    -- SIEM/integration fields
    siem_ref        VARCHAR(128),               -- External SIEM ticket ID
    tags            TEXT[]                       -- e.g. ARRAY['ransomware','persistence']
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents (assigned_to);

-- ============================================================
-- INCIDENT COMMENTS TABLE
-- Audit trail of analyst notes on each incident
-- ============================================================
CREATE TABLE IF NOT EXISTS incident_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    body        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_comments_incident ON incident_comments (incident_id);

-- ============================================================
-- MODEL VERSIONS TABLE
-- Tracks every trained model for rollback support
-- ============================================================
CREATE TABLE IF NOT EXISTS model_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_tag     VARCHAR(64) UNIQUE NOT NULL,  -- e.g. "lgb_v3_20260314"
    model_type      VARCHAR(32) NOT NULL CHECK (model_type IN ('lightgbm', 'isolation_forest', 'malgan')),
    file_path       TEXT NOT NULL,               -- Absolute path to .pkl / .pt file
    file_size_bytes BIGINT,
    checksum_sha256 CHAR(64),

    -- Training metadata
    trained_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trained_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    ember_samples   INTEGER,                     -- Training set size
    val_auc         FLOAT,
    val_accuracy    FLOAT,
    evasion_rate    FLOAT,
    antifragility_index FLOAT,

    is_active       BOOLEAN NOT NULL DEFAULT FALSE,  -- Only one active per type
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_model_versions_type ON model_versions (model_type);
CREATE INDEX IF NOT EXISTS idx_model_versions_active ON model_versions (is_active);

-- ============================================================
-- HARDENING ROUNDS TABLE
-- Records each GAN attack-defend cycle
-- ============================================================
CREATE TABLE IF NOT EXISTS hardening_rounds (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    round_number        INTEGER NOT NULL,
    model_version_id    UUID REFERENCES model_versions(id) ON DELETE SET NULL,

    evasive_samples     INTEGER,
    removed_poisoned    INTEGER,
    evasion_rate_before FLOAT,
    evasion_rate_after  FLOAT,
    antifragility_index FLOAT,

    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    duration_seconds    INTEGER,
    notes               TEXT
);

-- ============================================================
-- AUDIT LOG TABLE
-- Immutable record of all privileged actions
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,           -- Sequential for forensics
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_name  VARCHAR(64),                     -- Denormalized in case user deleted
    action      VARCHAR(128) NOT NULL,           -- e.g. "scan.create", "incident.resolve"
    resource    VARCHAR(128),                    -- e.g. "incident:uuid"
    detail      JSONB,                           -- Arbitrary structured context
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at DESC);

-- ============================================================
-- TRIGGER: auto-update incidents.updated_at
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_incidents_updated_at ON incidents;
CREATE TRIGGER trg_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- SEED DATA: default users
-- Passwords are sha256_crypt hashes — same algorithm as auth.py
-- Run generate_seed_hashes.py to regenerate these hashes.
-- ============================================================

-- Hashes generated with: passlib.hash.sha256_crypt.hash("navigo-admin-2026")
-- Replace these at first boot with production passwords.
INSERT INTO users (username, password_hash, role) VALUES
    ('admin',   '$5$rounds=535000$PLACEHOLDER_ADMIN_HASH',   'admin'),
    ('analyst', '$5$rounds=535000$PLACEHOLDER_ANALYST_HASH', 'analyst')
ON CONFLICT (username) DO NOTHING;

-- Note: Run db/generate_seed_hashes.py to get real hashes, then
-- UPDATE users SET password_hash = '...' WHERE username = 'admin';
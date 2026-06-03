-- ═══════════════════════════════════════════════════════════════
-- AEGIS Database Schema v2.0
-- Run this in Supabase SQL Editor to create all required tables
-- Includes tables for all 10 advanced features
-- ═══════════════════════════════════════════════════════════════

-- Users table (stores ZK public hash, NOT passwords)
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    public_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '24 hours'
);

-- Audit log chain (tamper-proof)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    hash TEXT UNIQUE NOT NULL,
    previous_hash TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    threat_level TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Recent events (for dashboard display, auto-cleaned)
CREATE TABLE IF NOT EXISTS recent_events (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    process TEXT,
    pid INTEGER,
    file_path TEXT,
    network_ip TEXT,
    port INTEGER DEFAULT 0,
    threat_score FLOAT DEFAULT 0,
    threat_level TEXT DEFAULT 'safe',
    event_type TEXT DEFAULT 'file_open',
    -- Feature 2: IOC enrichment
    ioc_matched BOOLEAN DEFAULT FALSE,
    ioc_confidence TEXT DEFAULT 'none',
    -- Feature 7: MITRE tagging
    mitre_techniques JSONB DEFAULT '[]',
    mitre_technique_count INTEGER DEFAULT 0,
    -- Feature 5: UEBA
    ueba_score FLOAT DEFAULT 0,
    ueba_user TEXT DEFAULT 'system',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Feature 3: Playbook Action Ledger ─────────────────────────
CREATE TABLE IF NOT EXISTS action_ledger (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    action_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    action_name TEXT NOT NULL,
    target TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    undo_payload JSONB DEFAULT '{}',
    status TEXT DEFAULT 'executed',
    executed_at TIMESTAMPTZ DEFAULT NOW(),
    undone_at TIMESTAMPTZ
);

-- ─── Feature 4: Honeypot Alerts ────────────────────────────────
CREATE TABLE IF NOT EXISTS honeypot_alerts (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    pid INTEGER,
    process TEXT,
    source_ip TEXT,
    resource_type TEXT,
    resource_path TEXT,
    severity TEXT DEFAULT 'critical',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Feature 5: Memory Forensics Captures ──────────────────────
CREATE TABLE IF NOT EXISTS forensics_captures (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    capture_id TEXT UNIQUE NOT NULL,
    pid INTEGER,
    process TEXT,
    threat_score FLOAT,
    trigger_source TEXT,
    memory_regions JSONB DEFAULT '[]',
    yara_matches JSONB DEFAULT '[]',
    status TEXT DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Feature 9: Federated Learning Rounds ──────────────────────
CREATE TABLE IF NOT EXISTS federated_rounds (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    round_number INTEGER NOT NULL,
    num_clients INTEGER,
    total_samples INTEGER,
    dp_epsilon FLOAT DEFAULT 0.1,
    model_version TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Indexes for Performance ───────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_threat_level ON audit_logs(threat_level);
CREATE INDEX IF NOT EXISTS idx_recent_events_created_at ON recent_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recent_events_threat_level ON recent_events(threat_level);
CREATE INDEX IF NOT EXISTS idx_recent_events_ioc ON recent_events(ioc_matched);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_action_ledger_incident ON action_ledger(incident_id);
CREATE INDEX IF NOT EXISTS idx_honeypot_alerts_created ON honeypot_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_forensics_captures_id ON forensics_captures(capture_id);

-- ─── Auto-Cleanup: Delete events older than 7 days ─────────────

CREATE OR REPLACE FUNCTION delete_old_events()
RETURNS trigger AS $$
BEGIN
    DELETE FROM recent_events WHERE created_at < NOW() - INTERVAL '7 days';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS cleanup_events ON recent_events;
CREATE TRIGGER cleanup_events
    AFTER INSERT ON recent_events
    EXECUTE FUNCTION delete_old_events();

-- ─── Auto-Cleanup: Delete expired sessions ─────────────────────

CREATE OR REPLACE FUNCTION delete_expired_sessions()
RETURNS trigger AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS cleanup_sessions ON sessions;
CREATE TRIGGER cleanup_sessions
    AFTER INSERT ON sessions
    EXECUTE FUNCTION delete_expired_sessions();

-- ═══════════════════════════════════════════════════════════════
-- Row Level Security (RLS) — Optional but recommended
-- ═══════════════════════════════════════════════════════════════

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE recent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE honeypot_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensics_captures ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_rounds ENABLE ROW LEVEL SECURITY;

-- Allow the service role full access (backend uses service key)
CREATE POLICY "Service role full access" ON users FOR ALL USING (true);
CREATE POLICY "Service role full access" ON sessions FOR ALL USING (true);
CREATE POLICY "Service role full access" ON audit_logs FOR ALL USING (true);
CREATE POLICY "Service role full access" ON recent_events FOR ALL USING (true);
CREATE POLICY "Service role full access" ON action_ledger FOR ALL USING (true);
CREATE POLICY "Service role full access" ON honeypot_alerts FOR ALL USING (true);
CREATE POLICY "Service role full access" ON forensics_captures FOR ALL USING (true);
CREATE POLICY "Service role full access" ON federated_rounds FOR ALL USING (true);

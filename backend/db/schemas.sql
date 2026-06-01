-- ═══════════════════════════════════════════════════════════════
-- AEGIS Database Schema
-- Run this in Supabase SQL Editor to create all required tables
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
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Indexes for Performance ───────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_threat_level ON audit_logs(threat_level);
CREATE INDEX IF NOT EXISTS idx_recent_events_created_at ON recent_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

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

-- Allow the service role full access (backend uses service key)
CREATE POLICY "Service role full access" ON users FOR ALL USING (true);
CREATE POLICY "Service role full access" ON sessions FOR ALL USING (true);
CREATE POLICY "Service role full access" ON audit_logs FOR ALL USING (true);
CREATE POLICY "Service role full access" ON recent_events FOR ALL USING (true);

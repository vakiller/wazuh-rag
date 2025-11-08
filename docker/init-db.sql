-- PostgreSQL Database Schema for RAG Wazuh System
-- This script creates all necessary tables for the three components

-- ============================================================================
-- Phase 1: Wazuh Alerts Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    document_id VARCHAR(255) NOT NULL UNIQUE,
    index_name VARCHAR(255),

    -- Agent information
    agent_id VARCHAR(50),
    agent_name VARCHAR(255),
    agent_ip INET,

    -- Rule information
    rule_id VARCHAR(50) NOT NULL,
    rule_level INTEGER NOT NULL,
    rule_description TEXT,
    rule_groups TEXT[],  -- PostgreSQL array

    -- MITRE ATT&CK
    mitre_techniques TEXT[],
    mitre_tactics TEXT[],

    -- Network information
    source_ip INET,
    source_port INTEGER,
    dest_ip INET,
    dest_port INTEGER,
    protocol VARCHAR(50),

    -- File information
    file_path TEXT,
    file_hash VARCHAR(255),

    -- Process information
    process_name VARCHAR(255),
    process_id INTEGER,
    process_parent_name VARCHAR(255),
    command_line TEXT,

    -- Windows event information
    win_eventid INTEGER,

    -- User information
    user_name VARCHAR(255),
    user_domain VARCHAR(255),

    -- Raw log content
    full_log TEXT,

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indices for alerts table
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_level ON alerts(rule_level);
CREATE INDEX IF NOT EXISTS idx_alerts_document_id ON alerts(document_id);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dest_ip ON alerts(dest_ip);


-- ============================================================================
-- Phase 2: Knowledge Base Table (for FAISS metadata)
-- ============================================================================

CREATE TABLE IF NOT EXISTS knowledge (
    vector_id INTEGER PRIMARY KEY,
    opencti_id VARCHAR(255) NOT NULL UNIQUE,
    standard_id VARCHAR(255),
    entity_type VARCHAR(100) NOT NULL,
    name VARCHAR(500) NOT NULL,
    content TEXT NOT NULL,
    metadata JSONB,  -- PostgreSQL JSONB for flexible metadata
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    confidence INTEGER,
    indexed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indices for knowledge table
CREATE INDEX IF NOT EXISTS idx_knowledge_entity_type ON knowledge(entity_type);
CREATE INDEX IF NOT EXISTS idx_knowledge_opencti_id ON knowledge(opencti_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_updated_at ON knowledge(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_knowledge_metadata ON knowledge USING GIN (metadata);


-- ============================================================================
-- Phase 3: Reports Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,

    -- Alert summary
    hosts TEXT[],  -- Array of affected hosts
    agents TEXT[], -- Array of affected agents
    alerts_count INTEGER NOT NULL,

    -- MITRE analysis
    mitre_list JSONB,  -- Array of MITRE techniques

    -- LLM analysis results
    summary TEXT,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    details JSONB,  -- Full LLM output
    iocs JSONB,  -- Extracted IOCs
    suggested_actions JSONB,  -- Remediation steps

    -- Context used for analysis
    faiss_context TEXT
);

-- Indices for reports table
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_window ON reports(window_start, window_end);
CREATE INDEX IF NOT EXISTS idx_reports_risk_score ON reports(risk_score DESC);


-- ============================================================================
-- State Tracking Table (replaces JSON state files)
-- ============================================================================

CREATE TABLE IF NOT EXISTS sync_state (
    component VARCHAR(100) PRIMARY KEY,  -- 'wazuh_retrieval', 'knowledge_ingest', 'llm_analysis'
    last_sync_timestamp TIMESTAMPTZ,
    last_sync_count INTEGER DEFAULT 0,
    state_data JSONB,  -- Additional state data
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial state for all components
INSERT INTO sync_state (component, last_sync_timestamp, last_sync_count, state_data)
VALUES
    ('wazuh_retrieval', NULL, 0, '{}'),
    ('knowledge_ingest', NULL, 0, '{}'),
    ('llm_analysis_hourly', NULL, 0, '{}'),
    ('llm_analysis_daily', NULL, 0, '{}')
ON CONFLICT (component) DO NOTHING;


-- ============================================================================
-- Helper Functions
-- ============================================================================

-- Function to get last sync timestamp for a component
CREATE OR REPLACE FUNCTION get_last_sync_timestamp(comp VARCHAR)
RETURNS TIMESTAMPTZ AS $$
BEGIN
    RETURN (SELECT last_sync_timestamp FROM sync_state WHERE component = comp);
END;
$$ LANGUAGE plpgsql;

-- Function to update sync state
CREATE OR REPLACE FUNCTION update_sync_state(
    comp VARCHAR,
    sync_ts TIMESTAMPTZ,
    sync_count INTEGER,
    data JSONB DEFAULT '{}'
)
RETURNS VOID AS $$
BEGIN
    UPDATE sync_state
    SET
        last_sync_timestamp = sync_ts,
        last_sync_count = sync_count,
        state_data = data,
        updated_at = CURRENT_TIMESTAMP
    WHERE component = comp;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- Grants (adjust username as needed)
-- ============================================================================

-- Grant permissions to the wazuh_user
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO wazuh_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO wazuh_user;

CREATE TABLE IF NOT EXISTS gate_decisions (
    id TEXT PRIMARY KEY NOT NULL,
    agent_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    gate_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    computed_hash TEXT,
    decided_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_records (
    id TEXT PRIMARY KEY NOT NULL,
    agent_name TEXT NOT NULL,
    layers_hashed INTEGER NOT NULL DEFAULT 0,
    drift_detected INTEGER NOT NULL DEFAULT 0,
    compliance_status TEXT NOT NULL,
    scanned_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gate_decisions_agent ON gate_decisions(agent_name);
CREATE INDEX IF NOT EXISTS idx_gate_decisions_type ON gate_decisions(gate_type);
CREATE INDEX IF NOT EXISTS idx_scan_records_agent ON scan_records(agent_name);

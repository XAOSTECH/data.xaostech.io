-- Consent Records Table
CREATE TABLE IF NOT EXISTS consent_records (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  accepted BOOLEAN DEFAULT 0,
  categories TEXT DEFAULT '[]',
  preferences TEXT DEFAULT '{}',
  reason TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER,
  deleted_at INTEGER
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_consent_user ON consent_records(user_id);
CREATE INDEX IF NOT EXISTS idx_consent_accepted ON consent_records(accepted);
CREATE INDEX IF NOT EXISTS idx_consent_created ON consent_records(created_at);

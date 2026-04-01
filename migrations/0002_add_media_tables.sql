-- Media storage tables for data.xaostech.io (data-db).
-- Required by /media/quota, /media/upload, /media/list, /media/delete endpoints.

CREATE TABLE IF NOT EXISTS user_quota (
  user_id   TEXT PRIMARY KEY,
  used_gb   REAL    NOT NULL DEFAULT 0,
  limit_gb  REAL    NOT NULL DEFAULT 10,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS media_files (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  key         TEXT NOT NULL UNIQUE,
  size_bytes  INTEGER NOT NULL,
  type        TEXT NOT NULL,
  uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at  DATETIME
);

CREATE INDEX IF NOT EXISTS idx_user_quota_user    ON user_quota(user_id);
CREATE INDEX IF NOT EXISTS idx_media_files_user   ON media_files(user_id);
CREATE INDEX IF NOT EXISTS idx_media_files_key    ON media_files(key);

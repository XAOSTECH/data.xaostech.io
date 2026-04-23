-- Trove Discovery Posts Table
CREATE TABLE IF NOT EXISTS trove_posts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  content TEXT NOT NULL,
  author_id TEXT NOT NULL,
  excerpt TEXT,
  artist TEXT,
  album TEXT,
  genre TEXT,
  release_year INTEGER,
  listen_url TEXT,
  cover_image_url TEXT,
  status TEXT DEFAULT 'draft', -- draft | published
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  published_at INTEGER,
  FOREIGN KEY (author_id) REFERENCES users(id)
);

-- Tags for discovery posts
CREATE TABLE IF NOT EXISTS trove_tags (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Junction table for post <-> tag
CREATE TABLE IF NOT EXISTS trove_post_tags (
  post_id TEXT NOT NULL,
  tag_id TEXT NOT NULL,
  PRIMARY KEY (post_id, tag_id),
  FOREIGN KEY (post_id) REFERENCES trove_posts(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES trove_tags(id) ON DELETE CASCADE
);

-- Comments on trove posts
CREATE TABLE IF NOT EXISTS trove_comments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  content TEXT NOT NULL,
  author_id TEXT,
  author_name TEXT,
  post_id TEXT NOT NULL,
  parent_comment_id TEXT,
  status TEXT DEFAULT 'approved', -- approved | pending | spam
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (author_id) REFERENCES users(id),
  FOREIGN KEY (post_id) REFERENCES trove_posts(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_comment_id) REFERENCES trove_comments(id) ON DELETE CASCADE
);

-- Users table (synced from account/api workers)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  github_id TEXT UNIQUE,
  username TEXT,
  email TEXT,
  avatar_url TEXT,
  role TEXT DEFAULT 'user', -- user | admin | owner
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_trove_posts_slug ON trove_posts(slug);
CREATE INDEX IF NOT EXISTS idx_trove_posts_author ON trove_posts(author_id);
CREATE INDEX IF NOT EXISTS idx_trove_posts_status ON trove_posts(status);
CREATE INDEX IF NOT EXISTS idx_trove_posts_genre ON trove_posts(genre);
CREATE INDEX IF NOT EXISTS idx_trove_posts_published ON trove_posts(published_at);
CREATE INDEX IF NOT EXISTS idx_trove_comments_post ON trove_comments(post_id);
CREATE INDEX IF NOT EXISTS idx_trove_comments_author ON trove_comments(author_id);
CREATE INDEX IF NOT EXISTS idx_trove_tags_name ON trove_tags(name);
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

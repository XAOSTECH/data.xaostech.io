-- =============================================================================
-- edu.xaostech.io - Initial Schema
-- =============================================================================
-- Exercise history, user progress, and analytics
-- =============================================================================

-- Generated exercises table
CREATE TABLE IF NOT EXISTS exercises (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    category TEXT NOT NULL,
    topic TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    type TEXT NOT NULL,
    problem_json TEXT NOT NULL,
    solution_json TEXT NOT NULL,
    hints_json TEXT,
    validation_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    model_used TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    usage_count INTEGER DEFAULT 0,
    avg_score REAL DEFAULT 0,
    avg_time_seconds INTEGER DEFAULT 0
);

-- Index for common queries
CREATE INDEX IF NOT EXISTS idx_exercises_subject ON exercises(subject);
CREATE INDEX IF NOT EXISTS idx_exercises_category ON exercises(category);
CREATE INDEX IF NOT EXISTS idx_exercises_difficulty ON exercises(difficulty);
CREATE INDEX IF NOT EXISTS idx_exercises_topic ON exercises(topic);
CREATE INDEX IF NOT EXISTS idx_exercises_created ON exercises(created_at);

-- User progress tracking
CREATE TABLE IF NOT EXISTS user_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    exercise_id TEXT NOT NULL,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    answer_json TEXT NOT NULL,
    score INTEGER NOT NULL,
    passed BOOLEAN NOT NULL,
    points_earned INTEGER NOT NULL,
    hints_used INTEGER DEFAULT 0,
    time_taken_seconds INTEGER NOT NULL,
    FOREIGN KEY (exercise_id) REFERENCES exercises(id)
);

CREATE INDEX IF NOT EXISTS idx_progress_user ON user_progress(user_id);
CREATE INDEX IF NOT EXISTS idx_progress_exercise ON user_progress(exercise_id);
CREATE INDEX IF NOT EXISTS idx_progress_submitted ON user_progress(submitted_at);

-- User skill levels per subject
CREATE TABLE IF NOT EXISTS user_skills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    category TEXT,
    current_level TEXT DEFAULT 'beginner',
    total_points INTEGER DEFAULT 0,
    exercises_completed INTEGER DEFAULT 0,
    avg_score REAL DEFAULT 0,
    streak_days INTEGER DEFAULT 0,
    last_activity DATETIME,
    UNIQUE(user_id, subject, category)
);

CREATE INDEX IF NOT EXISTS idx_skills_user ON user_skills(user_id);
CREATE INDEX IF NOT EXISTS idx_skills_subject ON user_skills(subject);

-- Generation analytics
CREATE TABLE IF NOT EXISTS generation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_json TEXT NOT NULL,
    model_used TEXT NOT NULL,
    tokens_used INTEGER,
    neurons_used INTEGER,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    latency_ms INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_logs_created ON generation_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_logs_model ON generation_logs(model_used);

-- Exercise templates (pre-approved patterns)
CREATE TABLE IF NOT EXISTS exercise_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    category TEXT NOT NULL,
    type TEXT NOT NULL,
    template_json TEXT NOT NULL,
    system_prompt TEXT,
    approved BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_templates_subject ON exercise_templates(subject);
CREATE INDEX IF NOT EXISTS idx_templates_approved ON exercise_templates(approved);

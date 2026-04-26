CREATE TABLE trust_working_hours (
    user_id       UUID PRIMARY KEY,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    typical_start INT NOT NULL DEFAULT 8,
    typical_end   INT NOT NULL DEFAULT 20,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

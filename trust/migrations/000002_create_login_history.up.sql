CREATE TABLE trust_login_history (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL,
    ip_hash        TEXT NOT NULL,
    country        TEXT,
    asn            TEXT,
    timestamp      TIMESTAMPTZ NOT NULL,
    was_successful BOOLEAN NOT NULL,
    trust_score    FLOAT,
    decision       TEXT
);
CREATE INDEX idx_login_history_user_id  ON trust_login_history(user_id);
CREATE INDEX idx_login_history_timestamp ON trust_login_history(timestamp DESC);

CREATE TABLE trust_device_fingerprints (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    ua_hash          TEXT NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    seen_count       INT NOT NULL DEFAULT 1
);
CREATE INDEX idx_trust_devices_user_id ON trust_device_fingerprints(user_id);
CREATE UNIQUE INDEX idx_trust_devices_user_fp
    ON trust_device_fingerprints(user_id, fingerprint_hash);

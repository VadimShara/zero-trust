CREATE TABLE user_idp_links (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp        TEXT NOT NULL,
    sub        TEXT NOT NULL,
    email      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (idp, sub)
);
CREATE INDEX idx_idp_links_user_id ON user_idp_links(user_id);

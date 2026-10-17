-- A shared page password as a second way into a private status page, next to
-- the emailed code. Only its argon2id hash is kept, and turning the way off
-- keeps it, so turning it back on brings the same password back.
SET LOCAL lock_timeout = '5s';

ALTER TABLE status_page_access
    ADD COLUMN password_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN password_hash    TEXT,
    ADD COLUMN password_set_at  TIMESTAMPTZ,
    ADD COLUMN password_set_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT status_page_access_password_set_together
        CHECK ((password_hash IS NULL) = (password_set_at IS NULL)),
    ADD CONSTRAINT status_page_access_password_on_needs_one
        CHECK (NOT password_enabled OR password_hash IS NOT NULL),
    DROP CONSTRAINT status_page_access_needs_a_way_in,
    ADD CONSTRAINT status_page_access_needs_a_way_in
        CHECK (NOT protected OR email_enabled OR password_enabled);
CREATE INDEX idx_status_page_access_password_set_by
    ON status_page_access (password_set_by) WHERE password_set_by IS NOT NULL;

-- A password session names nobody: the password cannot tell people apart.
ALTER TABLE status_page_sessions
    DROP CONSTRAINT status_page_sessions_method_check,
    ADD CONSTRAINT status_page_sessions_method_check
        CHECK (method IN ('email', 'password')),
    ADD CONSTRAINT status_page_sessions_password_is_anonymous
        CHECK (method <> 'password' OR viewer_id IS NULL);

ALTER TABLE status_page_access_events
    DROP CONSTRAINT status_page_access_events_kind_check,
    ADD CONSTRAINT status_page_access_events_kind_check
        CHECK (kind IN ('code_sent', 'code_failed', 'signed_in', 'signed_out',
                        'passkey_added', 'passkey_removed', 'blocked', 'unblocked',
                        'password_failed')),
    DROP CONSTRAINT status_page_access_events_method_check,
    ADD CONSTRAINT status_page_access_events_method_check
        CHECK (method IN ('email', 'passkey', 'password'));

-- The password_set_at of the password that let this subscription in, so a
-- new password or turning it off ends what the old one let in.
ALTER TABLE status_page_subscribers ADD COLUMN via_password_at TIMESTAMPTZ;

ALTER TABLE status_page_subscribers DROP COLUMN IF EXISTS via_password_at;
DELETE FROM status_page_access_events WHERE kind = 'password_failed' OR method = 'password';
ALTER TABLE status_page_access_events
    DROP CONSTRAINT status_page_access_events_method_check,
    ADD CONSTRAINT status_page_access_events_method_check
        CHECK (method IN ('email', 'passkey')),
    DROP CONSTRAINT status_page_access_events_kind_check,
    ADD CONSTRAINT status_page_access_events_kind_check
        CHECK (kind IN ('code_sent', 'code_failed', 'signed_in', 'signed_out',
                        'passkey_added', 'passkey_removed', 'blocked', 'unblocked'));
DELETE FROM status_page_sessions WHERE method = 'password';
ALTER TABLE status_page_sessions
    DROP CONSTRAINT status_page_sessions_password_is_anonymous,
    DROP CONSTRAINT status_page_sessions_method_check,
    ADD CONSTRAINT status_page_sessions_method_check CHECK (method IN ('email'));
-- Closed rather than opened: an empty list admits nobody.
UPDATE status_page_access SET email_enabled = true WHERE protected AND NOT email_enabled;
DROP INDEX IF EXISTS idx_status_page_access_password_set_by;
ALTER TABLE status_page_access
    DROP CONSTRAINT status_page_access_needs_a_way_in,
    DROP CONSTRAINT status_page_access_password_on_needs_one,
    DROP CONSTRAINT status_page_access_password_set_together,
    DROP COLUMN password_set_by,
    DROP COLUMN password_set_at,
    DROP COLUMN password_hash,
    DROP COLUMN password_enabled,
    ADD CONSTRAINT status_page_access_needs_a_way_in CHECK (NOT protected OR email_enabled);

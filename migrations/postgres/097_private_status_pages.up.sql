-- Private status pages: a page only the people on its access list can open.
-- They sign in on the page's own host with an emailed code, then may save a
-- passkey. Visitors here are not app users, so none of this touches the
-- users, sessions or magic-link tables.

ALTER TABLE plans ADD COLUMN private_pages_enabled BOOLEAN NOT NULL DEFAULT false;
UPDATE plans SET private_pages_enabled = true, updated_at = now() WHERE id = 'team';

-- Lets a child row name its viewer and page together, so a composite FK keeps
-- a session, passkey or subscription from pointing at another page's viewer.
CREATE TABLE status_page_viewers (
    id                UUID PRIMARY KEY DEFAULT uuidv7(),
    status_page_id    UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email             CITEXT NOT NULL,
    email_verified_at TIMESTAMPTZ NOT NULL,
    last_seen_at      TIMESTAMPTZ,
    -- Kept rather than deleted: a domain rule would let a removed person
    -- straight back in.
    blocked_at        TIMESTAMPTZ,
    blocked_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (status_page_id, email),
    UNIQUE (id, status_page_id)
);
CREATE INDEX idx_status_page_viewers_blocked_by
    ON status_page_viewers (blocked_by) WHERE blocked_by IS NOT NULL;
CREATE TRIGGER trg_status_page_viewers_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_viewers
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

-- One row per page ever made private. Absent means public; going back to
-- public keeps the row, so the list and viewers survive the round trip.
CREATE TABLE status_page_access (
    status_page_id   UUID PRIMARY KEY REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    protected        BOOLEAN NOT NULL,
    email_enabled    BOOLEAN NOT NULL DEFAULT true,
    passkeys_enabled BOOLEAN NOT NULL DEFAULT true,
    recheck_days     INT CHECK (recheck_days IN (30, 90, 365)),
    session_days     INT CHECK (session_days IN (7, 30, 90)),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A private page with no way in would open for nobody.
    CONSTRAINT status_page_access_needs_a_way_in CHECK (NOT protected OR email_enabled)
);
CREATE TRIGGER trg_status_page_access_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_access
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

CREATE TABLE status_page_access_rules (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    status_page_id UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CONSTRAINT status_page_access_rules_kind_check
                       CHECK (kind IN ('address', 'domain')),
    value          CITEXT NOT NULL,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (status_page_id, kind, value)
);
CREATE INDEX idx_status_page_access_rules_created_by
    ON status_page_access_rules (created_by) WHERE created_by IS NOT NULL;
CREATE TRIGGER trg_status_page_access_rules_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_access_rules
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

CREATE TABLE status_page_viewer_passkeys (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    viewer_id      UUID NOT NULL,
    status_page_id UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    credential_id  BYTEA NOT NULL UNIQUE,
    credential     JSONB NOT NULL,
    -- The host it was minted on; a changed custom domain orphans it.
    rp_id          TEXT NOT NULL,
    nickname       TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (viewer_id, status_page_id)
        REFERENCES status_page_viewers (id, status_page_id) ON DELETE CASCADE
);
CREATE INDEX idx_status_page_viewer_passkeys_page_viewer
    ON status_page_viewer_passkeys (status_page_id, viewer_id);
CREATE TRIGGER trg_status_page_viewer_passkeys_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_viewer_passkeys
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

CREATE TABLE status_page_webauthn_states (
    state_hash     TEXT PRIMARY KEY,
    status_page_id UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Set for a registration; NULL is a sign-in, where the authenticator
    -- names the viewer.
    viewer_id      UUID,
    state          JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (viewer_id, status_page_id)
        REFERENCES status_page_viewers (id, status_page_id) ON DELETE CASCADE
);
CREATE INDEX idx_status_page_webauthn_states_expires ON status_page_webauthn_states (expires_at);
CREATE INDEX idx_status_page_webauthn_states_page_viewer
    ON status_page_webauthn_states (status_page_id, viewer_id);
CREATE TRIGGER trg_status_page_webauthn_states_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_webauthn_states
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

-- The sign-in mail: a link and a code, as for the app's own magic links. A
-- row exists only for an address the list let in. Plain SHA-256 throughout:
-- the link token is 256 random bits, and the code is worth nothing without the
-- browser nonce it is bound to, which is stored hashed as well.
CREATE TABLE status_page_access_codes (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    status_page_id UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email          CITEXT NOT NULL,
    token_hash     TEXT NOT NULL UNIQUE,
    code_hash      TEXT NOT NULL,
    code_spent_at  TIMESTAMPTZ,
    nonce_hash     TEXT NOT NULL,
    sent_at        TIMESTAMPTZ,
    superseded_at  TIMESTAMPTZ,
    used_at        TIMESTAMPTZ,
    redeemed_via   TEXT CONSTRAINT status_page_access_codes_redeemed_via_check
                       CHECK (redeemed_via IN ('link', 'code')),
    expires_at     TIMESTAMPTZ NOT NULL,
    ip_hash        TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_status_page_access_codes_nonce
    ON status_page_access_codes (nonce_hash) WHERE used_at IS NULL AND code_spent_at IS NULL;
CREATE INDEX idx_status_page_access_codes_sent
    ON status_page_access_codes (status_page_id, email, sent_at);
CREATE INDEX idx_status_page_access_codes_expires ON status_page_access_codes (expires_at);
CREATE TRIGGER trg_status_page_access_codes_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_access_codes
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

CREATE TABLE status_page_sessions (
    id_hash         TEXT PRIMARY KEY,
    status_page_id  UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    method          TEXT NOT NULL CONSTRAINT status_page_sessions_method_check
                        CHECK (method IN ('email')),
    viewer_id       UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL lasts until sign-out, block or the list stops matching.
    expires_at      TIMESTAMPTZ,
    ip_hash         TEXT,
    user_agent_hash TEXT,
    CONSTRAINT status_page_sessions_email_names_viewer
        CHECK (method <> 'email' OR viewer_id IS NOT NULL),
    FOREIGN KEY (viewer_id, status_page_id)
        REFERENCES status_page_viewers (id, status_page_id) ON DELETE CASCADE
);
CREATE INDEX idx_status_page_sessions_viewer
    ON status_page_sessions (viewer_id, status_page_id) WHERE viewer_id IS NOT NULL;
CREATE INDEX idx_status_page_sessions_page ON status_page_sessions (status_page_id);
CREATE INDEX idx_status_page_sessions_expires
    ON status_page_sessions (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_status_page_sessions_last_used ON status_page_sessions (last_used_at);
CREATE TRIGGER trg_status_page_sessions_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_sessions
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

-- Sessions never expire by default, so a sign-in log alone cannot say who
-- still reads the page. One row per viewer per day visited.
CREATE TABLE status_page_viewer_days (
    viewer_id      UUID NOT NULL,
    day            DATE NOT NULL,
    status_page_id UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    PRIMARY KEY (viewer_id, day),
    FOREIGN KEY (viewer_id, status_page_id)
        REFERENCES status_page_viewers (id, status_page_id) ON DELETE CASCADE
);
CREATE INDEX idx_status_page_viewer_days_day ON status_page_viewer_days (day);
CREATE INDEX idx_status_page_viewer_days_page ON status_page_viewer_days (status_page_id);
CREATE TRIGGER trg_status_page_viewer_days_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_viewer_days
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

-- Month-partitioned; the PK must include the partition key. An attempt from
-- an address not on the list names no viewer and stores no address.
CREATE TABLE status_page_access_events (
    id              UUID NOT NULL DEFAULT uuidv7(),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    status_page_id  UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    viewer_id       UUID,
    kind            TEXT NOT NULL CONSTRAINT status_page_access_events_kind_check
                        CHECK (kind IN ('code_sent', 'code_failed', 'signed_in', 'signed_out',
                                        'passkey_added', 'passkey_removed', 'blocked', 'unblocked')),
    method          TEXT CONSTRAINT status_page_access_events_method_check
                        CHECK (method IN ('email', 'passkey')),
    failure_reason  TEXT,
    -- The member who blocked or unblocked.
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_hash         TEXT,
    user_agent_hash TEXT,
    PRIMARY KEY (id, occurred_at),
    FOREIGN KEY (viewer_id, status_page_id)
        REFERENCES status_page_viewers (id, status_page_id) ON DELETE CASCADE
) PARTITION BY RANGE (occurred_at);
CREATE TABLE status_page_access_events_default PARTITION OF status_page_access_events DEFAULT;
CREATE INDEX idx_status_page_access_events_viewer
    ON status_page_access_events (viewer_id, occurred_at DESC) WHERE viewer_id IS NOT NULL;
CREATE INDEX idx_status_page_access_events_page
    ON status_page_access_events (status_page_id, occurred_at DESC);
CREATE INDEX idx_status_page_access_events_occurred_at ON status_page_access_events (occurred_at);
CREATE INDEX idx_status_page_access_events_actor
    ON status_page_access_events (actor_id) WHERE actor_id IS NOT NULL;
CREATE TRIGGER trg_status_page_access_events_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON status_page_access_events
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

-- On a private page every subscription belongs to a signed-in viewer, so
-- blocking them or losing the rule that let them in ends it.
ALTER TABLE status_page_subscribers ADD COLUMN viewer_id UUID;
ALTER TABLE status_page_subscribers
    ADD CONSTRAINT status_page_subscribers_viewer_fkey
    FOREIGN KEY (viewer_id, status_page_id)
    REFERENCES status_page_viewers (id, status_page_id) ON DELETE CASCADE;
CREATE INDEX idx_status_page_subscribers_viewer
    ON status_page_subscribers (viewer_id, status_page_id) WHERE viewer_id IS NOT NULL;

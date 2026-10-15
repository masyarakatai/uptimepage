-- Fail the boot rather than queue every incident write behind the change.
SET LOCAL lock_timeout = '5s';

-- Updates posted to a maintenance window, the way incidents have them. The
-- phase is fixed when the update is posted, so moving the window later does
-- not relabel what was already said.
CREATE TABLE maintenance_updates (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    maintenance_id UUID NOT NULL REFERENCES maintenance_windows(id) ON DELETE CASCADE,
    posted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    phase          TEXT NOT NULL CHECK (phase IN ('scheduled', 'in_progress', 'completed')),
    message        TEXT NOT NULL CHECK (char_length(message) BETWEEN 1 AND 2000),
    author         UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_maintenance_updates_window
    ON maintenance_updates (maintenance_id, posted_at);
-- The subscriber fan-out reads every update inside its lookback, all orgs at once.
CREATE INDEX idx_maintenance_updates_posted
    ON maintenance_updates (posted_at);
CREATE INDEX idx_maintenance_updates_author
    ON maintenance_updates (author) WHERE author IS NOT NULL;
CREATE TRIGGER trg_maintenance_updates_org_match
    BEFORE INSERT OR UPDATE OF maintenance_id, org_id ON maintenance_updates
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('maintenance_windows', 'maintenance_id');

-- A started window stays in the history of the pages that showed it after
-- its monitor leaves the page, is deleted, or is dropped from the window,
-- under the name the page gave the monitor. target_ref keeps the monitor's
-- id once the monitor is gone.
CREATE TABLE maintenance_status_pages (
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    maintenance_id  UUID NOT NULL REFERENCES maintenance_windows(id) ON DELETE CASCADE,
    status_page_id  UUID NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
    target_ref      UUID NOT NULL,
    component_name  TEXT NOT NULL,
    PRIMARY KEY (maintenance_id, status_page_id, target_ref)
);
CREATE INDEX idx_maintenance_status_pages_page
    ON maintenance_status_pages (status_page_id, maintenance_id);
CREATE TRIGGER trg_maintenance_status_pages_org_match
    BEFORE INSERT OR UPDATE OF maintenance_id, org_id ON maintenance_status_pages
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('maintenance_windows', 'maintenance_id');
CREATE TRIGGER trg_maintenance_status_pages_page_org_match
    BEFORE INSERT OR UPDATE OF status_page_id, org_id ON maintenance_status_pages
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('status_pages', 'status_page_id');

-- When a monitor joined a window that had already started. NULL when it was
-- in the window before the start, so it is covered from whatever start the
-- window has.
ALTER TABLE maintenance_window_components ADD COLUMN joined_at TIMESTAMPTZ;

-- The time a monitor spent in a started window that later dropped it. A page
-- counts an outage while the monitor was out of the window, and none while
-- it was in, however often it left and came back. joined_at as above.
CREATE TABLE maintenance_window_departures (
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    maintenance_id  UUID NOT NULL REFERENCES maintenance_windows(id) ON DELETE CASCADE,
    target_id       UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    joined_at       TIMESTAMPTZ,
    left_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (maintenance_id, target_id, left_at)
);
CREATE INDEX idx_maintenance_window_departures_target
    ON maintenance_window_departures (org_id, target_id);
CREATE TRIGGER trg_maintenance_window_departures_org_match
    BEFORE INSERT OR UPDATE OF maintenance_id, org_id ON maintenance_window_departures
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('maintenance_windows', 'maintenance_id');
CREATE TRIGGER trg_maintenance_window_departures_target_org
    BEFORE INSERT OR UPDATE OF target_id, org_id ON maintenance_window_departures
    FOR EACH ROW EXECUTE FUNCTION assert_target_in_same_org();

-- When an incident was last closed, by the database clock. ended_at can come
-- from the check that recovered or from where a recovery began, so it cannot
-- tell the closing update from one posted while the incident was open.
ALTER TABLE incidents ADD COLUMN resolved_at TIMESTAMPTZ;

-- An incident closed before this has its closing update's time, the moment a
-- close now records, or its end when it never had a public update.
UPDATE incidents i
SET resolved_at = COALESCE(
        (SELECT max(u.posted_at) FROM incident_updates u
         WHERE u.incident_id = i.id AND u.org_id = i.org_id AND u.phase = 'resolved'),
        i.ended_at)
WHERE i.ended_at IS NOT NULL;

ALTER TABLE status_page_subscriber_deliveries
    DROP CONSTRAINT status_page_subscriber_deliveries_event_kind_check,
    ADD CONSTRAINT status_page_subscriber_deliveries_event_kind_check
        CHECK (event_kind IN ('incident_update', 'maintenance', 'maintenance_update'));

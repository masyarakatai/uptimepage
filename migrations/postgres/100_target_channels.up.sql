-- A monitor's notification channels, one row per binding. The foreign keys
-- remove a binding in the same transaction that deletes its monitor or its
-- channel. Positions keep the saved order and may have gaps.
CREATE TABLE target_channels (
    target_id  UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    channel_id UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    position   INT  NOT NULL,
    PRIMARY KEY (target_id, channel_id)
);

CREATE INDEX target_channels_channel_idx ON target_channels (channel_id);

CREATE TRIGGER trg_target_channels_target_org_match
    BEFORE INSERT OR UPDATE OF target_id, org_id ON target_channels
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('targets', 'target_id');
CREATE TRIGGER trg_target_channels_channel_org_match
    BEFORE INSERT OR UPDATE OF channel_id, org_id ON target_channels
    FOR EACH ROW EXECUTE FUNCTION assert_org_matches_parent('notification_channels', 'channel_id');

-- A binding to a channel that no longer exists in the monitor's org pages
-- nobody, so it is not carried over. A repeated channel keeps its first place.
INSERT INTO target_channels (target_id, channel_id, org_id, position)
SELECT DISTINCT ON (t.id, c.id) t.id, c.id, t.org_id, (e.n - 1)::int
  FROM targets t
 CROSS JOIN LATERAL jsonb_array_elements(
       CASE jsonb_typeof(t.alerts) WHEN 'array' THEN t.alerts ELSE '[]'::jsonb END
     ) WITH ORDINALITY AS e(v, n)
  JOIN notification_channels c
    ON c.org_id = t.org_id AND c.id::text = e.v->>'channel_id'
 ORDER BY t.id, c.id, e.n;

-- The column stays for builds that still read it, frozen at the copy above: a
-- write to it would land where nothing reads, so it is refused instead.
CREATE FUNCTION targets_alerts_frozen() RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'INSERT' AND NEW.alerts <> '[]'::jsonb)
       OR (TG_OP = 'UPDATE' AND NEW.alerts IS DISTINCT FROM OLD.alerts) THEN
        RAISE EXCEPTION 'targets.alerts is read-only: channel bindings live in target_channels';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

CREATE TRIGGER trg_targets_alerts_frozen
    BEFORE INSERT OR UPDATE OF alerts ON targets
    FOR EACH ROW EXECUTE FUNCTION targets_alerts_frozen();

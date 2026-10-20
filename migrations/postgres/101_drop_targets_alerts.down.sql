-- Back to the state after 100: the JSON copy rebuilt from target_channels,
-- then frozen again. The guard comes last; it refuses the rebuild.
ALTER TABLE targets ADD COLUMN alerts JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE targets t
   SET alerts = COALESCE((
           SELECT jsonb_agg(jsonb_build_object('channel_id', tc.channel_id)
                            ORDER BY tc.position, tc.channel_id)
             FROM target_channels tc
            WHERE tc.target_id = t.id), '[]'::jsonb);

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

-- Bindings have lived in target_channels since 100; the frozen JSON copy was
-- kept only for builds older than that.
DROP TRIGGER trg_targets_alerts_frozen ON targets;
DROP FUNCTION targets_alerts_frozen();
ALTER TABLE targets DROP COLUMN alerts;

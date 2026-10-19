-- The guard goes first: the rebuild below writes the column it refuses.
DROP TRIGGER trg_targets_alerts_frozen ON targets;
DROP FUNCTION targets_alerts_frozen();

UPDATE targets t
   SET alerts = COALESCE((
           SELECT jsonb_agg(jsonb_build_object('channel_id', tc.channel_id)
                            ORDER BY tc.position, tc.channel_id)
             FROM target_channels tc
            WHERE tc.target_id = t.id), '[]'::jsonb);

DROP TABLE target_channels;

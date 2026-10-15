DELETE FROM status_page_subscriber_deliveries WHERE event_kind = 'maintenance_update';
ALTER TABLE status_page_subscriber_deliveries
    DROP CONSTRAINT status_page_subscriber_deliveries_event_kind_check,
    ADD CONSTRAINT status_page_subscriber_deliveries_event_kind_check
        CHECK (event_kind IN ('incident_update', 'maintenance'));

-- Pages that kept a monitor's incident after the monitor left them; before
-- this, a link with a live monitor meant something else.
DELETE FROM incident_status_pages isp
USING incidents i
WHERE i.id = isp.incident_id AND i.org_id = isp.org_id AND i.target_id IS NOT NULL;

ALTER TABLE incidents DROP COLUMN resolved_at;
DROP TABLE maintenance_window_departures;
ALTER TABLE maintenance_window_components DROP COLUMN joined_at;
DROP TABLE maintenance_status_pages;
DROP TABLE maintenance_updates;

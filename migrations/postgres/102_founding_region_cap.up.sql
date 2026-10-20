-- Founding is sold with five probe regions per monitor, any five.
UPDATE plans SET max_regions = 5, updated_at = now() WHERE id = 'founding';

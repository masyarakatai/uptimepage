SET LOCAL lock_timeout = '5s';

-- `system` follows the OS light/dark setting and replaces 'default' as the
-- default. Accounts still on the old default move to it; any other pick stays.
ALTER TABLE users DROP CONSTRAINT users_theme_check;
ALTER TABLE users ADD CONSTRAINT users_theme_check CHECK (theme IN (
    'system', 'default', 'terminal', 'winter',
    'dark', 'night', 'dim', 'nord', 'dracula',
    'corporate', 'light', 'cupcake', 'cyberpunk', 'synthwave'
));
ALTER TABLE users ALTER COLUMN theme SET DEFAULT 'system';
UPDATE users SET theme = 'system' WHERE theme = 'default';

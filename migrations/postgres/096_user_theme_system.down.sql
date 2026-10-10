SET LOCAL lock_timeout = '5s';

UPDATE users SET theme = 'default' WHERE theme = 'system';
ALTER TABLE users ALTER COLUMN theme SET DEFAULT 'default';
ALTER TABLE users DROP CONSTRAINT users_theme_check;
ALTER TABLE users ADD CONSTRAINT users_theme_check CHECK (theme IN (
    'default', 'terminal', 'winter',
    'dark', 'night', 'dim', 'nord', 'dracula',
    'corporate', 'light', 'cupcake', 'cyberpunk', 'synthwave'
));

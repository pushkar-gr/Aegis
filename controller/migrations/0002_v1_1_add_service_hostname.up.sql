ALTER TABLE services ADD COLUMN hostname TEXT NOT NULL DEFAULT 'static-placeholder-hostname';

UPDATE services SET hostname = ip_port;

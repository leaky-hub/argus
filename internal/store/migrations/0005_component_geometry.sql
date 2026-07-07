-- Canvas geometry: a component's rendered size, so trust boundaries (and any
-- node) can be resized on the visual canvas and persist. -1 means "use the
-- default size for the kind" — the canvas decides, same convention as pos_x/y.
ALTER TABLE threat_components ADD COLUMN pos_w REAL NOT NULL DEFAULT -1;
ALTER TABLE threat_components ADD COLUMN pos_h REAL NOT NULL DEFAULT -1;

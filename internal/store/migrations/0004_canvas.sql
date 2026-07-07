-- Visual canvas for threat models: persisted node positions on components,
-- and data flows (directed edges between components, optionally labeled).
-- Layout is presentation state — it never affects enumeration, status, or the
-- gate. Position -1/-1 means "not placed yet"; the canvas auto-lays those out.

ALTER TABLE threat_components ADD COLUMN pos_x REAL NOT NULL DEFAULT -1;
ALTER TABLE threat_components ADD COLUMN pos_y REAL NOT NULL DEFAULT -1;

CREATE TABLE threat_flows (
  id       TEXT PRIMARY KEY,
  model_id TEXT NOT NULL REFERENCES threat_models(id) ON DELETE CASCADE,
  from_id  TEXT NOT NULL REFERENCES threat_components(id) ON DELETE CASCADE,
  to_id    TEXT NOT NULL REFERENCES threat_components(id) ON DELETE CASCADE,
  label    TEXT NOT NULL DEFAULT ''   -- what moves along the edge ("user creds", "order events")
);
CREATE INDEX idx_threat_flows_model ON threat_flows(model_id);

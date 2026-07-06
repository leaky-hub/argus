-- Threat modeling: a model scoped to a target/application, its components and
-- trust boundaries, the STRIDE threats enumerated over them, and the links that
-- tie a threat to real scan evidence (findings), the controls it touches, and a
-- curated mitigation. Threat CONTENT comes from the curated library
-- (internal/threatlib); risk/status is always human. An LLM may only suggest
-- (source='assisted'), never set status.

CREATE TABLE threat_models (
  id          TEXT PRIMARY KEY,
  target_id   TEXT NOT NULL DEFAULT '',   -- scoping target, or '' for a free-standing app
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL DEFAULT '',
  updated_at  TEXT NOT NULL
);

CREATE TABLE threat_components (
  id       TEXT PRIMARY KEY,
  model_id TEXT NOT NULL REFERENCES threat_models(id) ON DELETE CASCADE,
  kind     TEXT NOT NULL DEFAULT 'component', -- component | asset | boundary | external-entity
  name     TEXT NOT NULL,
  tech     TEXT NOT NULL DEFAULT '',          -- library key (web-app, database, object-store…)
  notes    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_threat_components_model ON threat_components(model_id);

CREATE TABLE threats (
  id           TEXT PRIMARY KEY,
  model_id     TEXT NOT NULL REFERENCES threat_models(id) ON DELETE CASCADE,
  component_id TEXT NOT NULL DEFAULT '',      -- the component/boundary, or '' if model-wide
  category     TEXT NOT NULL,                 -- STRIDE: spoofing|tampering|repudiation|info-disclosure|denial-of-service|elevation
  title        TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'open',  -- open | mitigated | accepted | transferred
  source       TEXT NOT NULL DEFAULT 'curated', -- curated | assisted (assisted = LLM-suggested, human-confirmed)
  mitigation   TEXT NOT NULL DEFAULT '',      -- suggested mitigation weakness id (from the library)
  created_at   TEXT NOT NULL,
  created_by   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_threats_model ON threats(model_id);

-- A threat's evidence and coverage: a finding (fingerprint), a compliance
-- control (e.g. ASVS:V5.3.4), or a mitigation weakness id.
CREATE TABLE threat_links (
  threat_id TEXT NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
  kind      TEXT NOT NULL,                    -- finding | control | mitigation
  ref       TEXT NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',         -- for finding links (fingerprint is target-scoped)
  PRIMARY KEY (threat_id, kind, ref, target_id)
);

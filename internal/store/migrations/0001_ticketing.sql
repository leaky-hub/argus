-- Ticketing: a work-tracking layer over findings. A ticket gathers evidence
-- (many findings, by stable fingerprint), owns the human workflow, and carries a
-- timeline. The severity rollup is NOT stored — it is computed at read time from
-- the linked findings' current severities, so it can never go stale.

CREATE TABLE tickets (
  id           TEXT PRIMARY KEY,
  title        TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'open',     -- open | in-progress | blocked | done
  priority     TEXT NOT NULL DEFAULT 'medium',   -- low | medium | high | urgent
  assignee     TEXT NOT NULL DEFAULT '',         -- username, or '' for unassigned
  target_id    TEXT NOT NULL DEFAULT '',         -- scoping context, or '' for none
  due_date     TEXT NOT NULL DEFAULT '',         -- ISO date, or ''
  external_url TEXT NOT NULL DEFAULT '',          -- linked issue URL (referenced, never scraped)
  external_id  TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  created_by   TEXT NOT NULL DEFAULT '',
  updated_at   TEXT NOT NULL
);

-- finding -> ticket, many-to-one. Target-scoped: a fingerprint is only stable
-- within a target's history, and two targets sharing code can collide.
CREATE TABLE ticket_links (
  ticket_id  TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  target_id  TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (ticket_id, finding_id, target_id)
);
CREATE INDEX idx_ticket_links_finding ON ticket_links(finding_id);

-- Timeline: human comments plus system events (status change, link) as one
-- ordered stream, distinguished by kind.
CREATE TABLE ticket_comments (
  id         TEXT PRIMARY KEY,
  ticket_id  TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL DEFAULT 'comment',    -- comment | event
  author     TEXT NOT NULL DEFAULT '',
  body       TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX idx_ticket_comments_ticket ON ticket_comments(ticket_id);

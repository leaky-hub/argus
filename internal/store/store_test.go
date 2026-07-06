package store

import "testing"

func TestOpenCreatesAndMigrates(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// The DB file lands in the given directory.
	if _, err := db.Exec(`INSERT INTO tickets (id, title, created_at, updated_at) VALUES ('tk-1','t','now','now')`); err != nil {
		t.Fatalf("tickets table missing or wrong: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO ticket_links (ticket_id, finding_id, target_id) VALUES ('tk-1','fp','t-1')`); err != nil {
		t.Fatalf("ticket_links: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO ticket_comments (id, ticket_id, created_at) VALUES ('c-1','tk-1','now')`); err != nil {
		t.Fatalf("ticket_comments: %v", err)
	}

	// A migration is recorded exactly once.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("schema_migrations has %d rows, want 1", n)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tickets (id, title, created_at, updated_at) VALUES ('tk-keep','t','now','now')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Reopening the same directory must not re-run migrations or wipe data.
	db2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var got string
	if err := db2.QueryRow(`SELECT title FROM tickets WHERE id = 'tk-keep'`).Scan(&got); err != nil {
		t.Fatalf("data lost across reopen: %v", err)
	}
	var n int
	db2.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n)
	if n != 1 {
		t.Errorf("migrations re-applied: %d rows, want 1", n)
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A link to a nonexistent ticket must be rejected (foreign_keys ON).
	if _, err := db.Exec(`INSERT INTO ticket_links (ticket_id, finding_id, target_id) VALUES ('nope','fp','t-1')`); err == nil {
		t.Error("foreign key not enforced: orphan link accepted")
	}
	// Cascade delete: removing a ticket removes its links.
	db.Exec(`INSERT INTO tickets (id, title, created_at, updated_at) VALUES ('tk-c','t','now','now')`)
	db.Exec(`INSERT INTO ticket_links (ticket_id, finding_id, target_id) VALUES ('tk-c','fp','t-1')`)
	db.Exec(`DELETE FROM tickets WHERE id = 'tk-c'`)
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM ticket_links WHERE ticket_id = 'tk-c'`).Scan(&n)
	if n != 0 {
		t.Errorf("cascade delete failed: %d orphan links remain", n)
	}
}

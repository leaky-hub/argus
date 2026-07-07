package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

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

	// Every embedded migration is recorded.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Errorf("schema_migrations has %d rows, want >= 1", n)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var applied int
	db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied)
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
	if n != applied {
		t.Errorf("migrations re-applied: %d rows, want %d (unchanged)", n, applied)
	}
}

// TestSchemaComplete asserts every table and index from every migration exists
// after Open. Each migration file holds several statements in one Exec call; if
// the driver ever executed only the first statement per call, tables would
// still exist (they come first) but the indexes would silently be gone.
func TestSchemaComplete(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	want := map[string]string{
		"tickets": "table", "ticket_links": "table", "ticket_comments": "table",
		"threat_models": "table", "threat_components": "table", "threats": "table", "threat_links": "table",
		"idx_ticket_links_finding": "index", "idx_ticket_comments_ticket": "index",
		"idx_threat_components_model": "index", "idx_threats_model": "index",
	}
	for name, kind := range want {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type=? AND name=?`, kind, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s %q missing from schema", kind, name)
		}
	}
}

// TestCorruptDBFailsClosed: a garbage argus.db must make Open fail with an
// error — never silently recreate (that would destroy the operator's tickets)
// and never panic. The corrupt file must be left in place for recovery.
func TestCorruptDBFailsClosed(t *testing.T) {
	dir := t.TempDir()
	garbage := []byte("this is not a sqlite database, it is 64 bytes of plain text!!!!")
	if err := os.WriteFile(filepath.Join(dir, dbFile), garbage, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(dir)
	if err == nil {
		db.Close()
		t.Fatal("Open succeeded on a corrupt database file")
	}
	after, rerr := os.ReadFile(filepath.Join(dir, dbFile))
	if rerr != nil || !bytes.Equal(after, garbage) {
		t.Errorf("corrupt file was altered or removed (err=%v)", rerr)
	}
}

// TestTruncatedDBIsEmptyDB documents SQLite's contract for a zero-byte file:
// it is a valid empty database, so Open migrates it like a fresh one.
func TestTruncatedDBIsEmptyDB(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dbFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open on zero-byte file: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO tickets (id, title, created_at, updated_at) VALUES ('tk-1','t','now','now')`); err != nil {
		t.Errorf("schema not usable after migrating a zero-byte file: %v", err)
	}
}

// TestReadOnlyDirFailsClosed: a read-only served root must fail Open with an
// error, not panic later on first write.
func TestReadOnlyDirFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	if db, err := Open(dir); err == nil {
		db.Close()
		t.Fatal("Open succeeded in a read-only directory")
	}
}

// TestForeignKeysHoldAcrossConnectionRecycling: foreign_keys is per-connection
// in SQLite. The DSN _pragma must re-apply it on every connection the pool
// opens, not only the first — force rapid recycling and check each time.
func TestForeignKeysHoldAcrossConnectionRecycling(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(time.Millisecond)
	for i := 0; i < 25; i++ {
		var on int
		if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
			t.Fatal(err)
		}
		if on != 1 {
			t.Fatalf("foreign_keys off on recycled connection (iteration %d)", i)
		}
		time.Sleep(2 * time.Millisecond)
	}
	// And a cascade still works on whatever connection serves it now.
	db.Exec(`INSERT INTO tickets (id, title, created_at, updated_at) VALUES ('tk-r','t','now','now')`)
	db.Exec(`INSERT INTO ticket_links (ticket_id, finding_id, target_id) VALUES ('tk-r','fp','')`)
	db.Exec(`DELETE FROM tickets WHERE id='tk-r'`)
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM ticket_links WHERE ticket_id='tk-r'`).Scan(&n)
	if n != 0 {
		t.Errorf("cascade failed on a recycled connection: %d orphan links", n)
	}
}

// TestConcurrentWritersAllSucceed: the single-connection pool plus the busy
// timeout must serialize concurrent writers without surfacing SQLITE_BUSY.
func TestConcurrentWritersAllSucceed(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const workers, each = 8, 20
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				id := fmt.Sprintf("tk-%d-%d", w, i)
				if _, err := db.Exec(`INSERT INTO tickets (id, title, created_at, updated_at) VALUES (?,?,?,?)`, id, "t", "now", "now"); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent insert failed: %v", err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM tickets`).Scan(&n)
	if n != workers*each {
		t.Errorf("rows = %d, want %d", n, workers*each)
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

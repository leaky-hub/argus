// Package store is Argus's embedded SQLite database: the one place structured,
// mutable, related app-level state lives (tickets and threat models), as opposed
// to the immutable run files and the file-based disposition/user/target stores.
//
// It uses modernc.org/sqlite — the pure-Go driver, no cgo — so the single-
// binary, local-first story holds. The database is `<root>/.appsec/argus.db`,
// created on first open; schema changes are forward-only numbered migrations
// under migrations/, applied at open and recorded in schema_migrations.
//
// The gate NEVER reads from here: dispositions stay file-based and remain the
// deterministic gate input. A ticket can write a "fixed" disposition through the
// existing store on an explicit, audited human action, but that is the only
// bridge — the DB does not own the gate.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const dbFile = "argus.db"

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps *sql.DB with Argus's open/migrate behavior. Callers use it like any
// database/sql handle; every query MUST use placeholders (never string-built
// SQL) — finding data and user text are hostile.
type DB struct {
	*sql.DB
}

// Open opens (creating if needed) the Argus database in dir — the served root's
// .appsec directory — and applies any pending migrations. foreign_keys and a
// busy timeout are set on every pooled connection; the journal runs in WAL mode.
func Open(dir string) (*DB, error) {
	path := filepath.Join(dir, dbFile)
	// _pragma params apply to every connection the driver opens, so foreign_keys
	// (per-connection, not persistent) and the busy timeout always hold.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One writer connection serializes writes, which keeps a low-concurrency,
	// local-first console clear of SQLITE_BUSY churn. WAL still serves reads
	// without blocking; this is plenty for a single-operator console.
	sqlDB.SetMaxOpenConns(1)
	db := &DB{sqlDB}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

// migrate applies every embedded migration not yet recorded, each in its own
// transaction, in lexical (numbered) order. Forward-only: there is no down path.
func (db *DB) migrate() error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: init migrations table: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("store: read migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		var seen int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&seen); err != nil {
			return fmt.Errorf("store: check migration %s: %w", version, err)
		}
		if seen > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: read %s: %w", name, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: apply %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			version, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: record %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit %s: %w", name, err)
		}
	}
	return nil
}

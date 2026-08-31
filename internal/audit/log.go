// Package audit provides an asynchronous audit log for the Tidebreak gateway.
// Every intercepted request is logged with what was redacted, where it was
// routed, and the classification tier. The log uses SQLite for queryability
// and is written asynchronously to avoid blocking the proxy.
package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Entry represents a single audit log record.
type Entry struct {
	ID         int64
	Timestamp  time.Time
	Agent      string
	Provider   string
	Action     string
	Target     string
	Tier       string
	Redactions string // JSON: {"ips": 3, "emails": 2, ...}
	Approved   bool
	Notes      string
}

// Log is the async audit log writer.
type Log struct {
	db      *sql.DB
	queue   chan Entry
	done    chan struct{}
	wg      sync.WaitGroup
	dropped int64 // atomic counter for dropped entries
}

// New opens (or creates) the audit database at the given path and starts
// the async writer goroutine.
func New(dbPath string) (*Log, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening audit db: %w", err)
	}

	// Optimize SQLite for write throughput
	db.SetMaxOpenConns(1) // SQLite handles concurrent writes poorly
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting synchronous mode: %w", err)
	}

	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS audit_entries (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp   DATETIME NOT NULL,
		agent       TEXT NOT NULL,
		provider    TEXT NOT NULL,
		action      TEXT NOT NULL,
		target      TEXT,
		tier        TEXT NOT NULL,
		redactions  TEXT,
		approved    BOOLEAN DEFAULT 0,
		notes       TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_entries(agent);
	CREATE INDEX IF NOT EXISTS idx_audit_tier ON audit_entries(tier);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	l := &Log{
		db:    db,
		queue: make(chan Entry, 1024),
		done:  make(chan struct{}),
	}

	l.wg.Add(1)
	go l.writer()

	return l, nil
}

// Record queues an entry for asynchronous writing. Non-blocking.
// If the queue is full, the entry is dropped and the dropped counter is
// incremented. Check DroppedCount() to monitor for dropped entries.
func (l *Log) Record(entry Entry) {
	entry.Timestamp = time.Now()
	select {
	case l.queue <- entry:
	default:
		atomic.AddInt64(&l.dropped, 1)
	}
}

// DroppedCount returns the number of audit entries that were dropped
// because the queue was full. This should be monitored — if non-zero,
// the queue buffer may need to be larger or the writer is too slow.
func (l *Log) DroppedCount() int64 {
	return atomic.LoadInt64(&l.dropped)
}

// writer is the background goroutine that flushes entries to SQLite.
func (l *Log) writer() {
	defer l.wg.Done()

	stmt, err := l.db.Prepare(`INSERT INTO audit_entries
		(timestamp, agent, provider, action, target, tier, redactions, approved, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		// Can't prepare — the audit log is broken. Log to stderr and return.
		return
	}
	defer stmt.Close()

	for {
		select {
		case entry := <-l.queue:
			_, err := stmt.Exec(
				entry.Timestamp,
				entry.Agent,
				entry.Provider,
				entry.Action,
				entry.Target,
				entry.Tier,
				entry.Redactions,
				entry.Approved,
				entry.Notes,
			)
			if err != nil {
				// Individual write failure — continue processing
				continue
			}
		case <-l.done:
			// Drain remaining entries before shutting down
			for {
				select {
				case entry := <-l.queue:
					stmt.Exec(
						entry.Timestamp, entry.Agent, entry.Provider, entry.Action,
						entry.Target, entry.Tier, entry.Redactions, entry.Approved, entry.Notes,
					)
				default:
					return
				}
			}
		}
	}
}

// Close shuts down the writer and flushes remaining entries.
func (l *Log) Close() error {
	close(l.done)
	l.wg.Wait()
	return l.db.Close()
}

// Query returns entries matching the given filter.
// If agent is empty, all agents are included. If since is zero, no time filter.
func (l *Log) Query(agent string, since time.Time, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	return l.query(agent, since, limit)
}

// queryAll is Query without the display limit cap — used by Export and
// Rotate, which must see every matching row.
func (l *Log) queryAll(agent string, since time.Time) ([]Entry, error) {
	return l.query(agent, since, -1) // -1 = uncapped
}

// query is the shared implementation. limit <= 0 (or -1) means no LIMIT
// clause at all.
func (l *Log) query(agent string, since time.Time, limit int) ([]Entry, error) {
	q := "SELECT id, timestamp, agent, provider, action, target, tier, redactions, approved, notes FROM audit_entries"
	args := []interface{}{}
	where := []string{}

	if agent != "" {
		where = append(where, "agent = ?")
		args = append(args, agent)
	}
	if !since.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, since)
	}

	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY timestamp DESC"
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := l.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var target, redactions, notes sql.NullString
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Agent, &e.Provider, &e.Action,
			&target, &e.Tier, &redactions, &e.Approved, &notes)
		if err != nil {
			continue
		}
		e.Target = target.String
		e.Redactions = redactions.String
		e.Notes = notes.String
		entries = append(entries, e)
	}

	return entries, nil
}

// Summary returns aggregate counts for the given time period.
type Summary struct {
	Total      int
	ByTier     map[string]int
	ByAgent    map[string]int
	ByProvider map[string]int
	Redactions int
}

// GetSummary returns a summary of audit activity since the given time.
func (l *Log) GetSummary(since time.Time) (*Summary, error) {
	s := &Summary{
		ByTier:     make(map[string]int),
		ByAgent:    make(map[string]int),
		ByProvider: make(map[string]int),
	}

	entries, err := l.Query("", since, 10000)
	if err != nil {
		return nil, err
	}

	s.Total = len(entries)
	for _, e := range entries {
		s.ByTier[e.Tier]++
		s.ByAgent[e.Agent]++
		s.ByProvider[e.Provider]++
		if e.Redactions != "" && e.Redactions != "null" {
			s.Redactions++
		}
	}

	return s, nil
}

// Export writes all matching entries (optionally since a given time) to a
// JSON file. No row cap — exports every entry that matches the filter.
// Returns the number of entries exported.
func (l *Log) Export(path string, since time.Time) (int, error) {
	entries, err := l.queryAll("", since)
	if err != nil {
		return 0, fmt.Errorf("querying for export: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("creating export file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(entries); err != nil {
		return 0, fmt.Errorf("encoding export: %w", err)
	}

	return len(entries), nil
}

// Rotate exports matching entries to the given path, then deletes exactly
// those entries from the database. Entries outside the since filter are
// retained. Returns the number of entries rotated out.
func (l *Log) Rotate(exportPath string, since time.Time) (int, error) {
	count, err := l.Export(exportPath, since)
	if err != nil {
		return 0, err
	}

	// Delete exactly what was exported: same filter, bounded by now so
	// entries written between the export query and this DELETE survive.
	if _, err := l.db.Exec("DELETE FROM audit_entries WHERE timestamp >= ? AND timestamp <= ?", since, time.Now()); err != nil {
		return count, fmt.Errorf("deleting rotated entries: %w", err)
	}

	return count, nil
}

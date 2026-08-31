package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// insertEntry writes an entry with an explicit timestamp, bypassing
// Record() which stamps time.Now() — regression tests need controlled
// timestamps to build a time window.
func insertEntry(t *testing.T, l *Log, ts time.Time, tier string) {
	t.Helper()
	_, err := l.db.Exec(`INSERT INTO audit_entries
		(timestamp, agent, provider, action, target, tier, redactions, approved, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, "test", "openai", "read", "/tmp/x", tier, "", false, "")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// Rotate must delete exactly the entries it exported, and nothing else.
// Regression test for the pre-fix behavior: DELETE ran unbounded
// (WHERE timestamp <= now) while the export was capped at 100 rows.
func TestRotateDeletesOnlyExportedEntries(t *testing.T) {
	log := newTestLog(t)

	now := time.Now()
	old := now.Add(-48 * time.Hour) // outside the 24h window
	recent := now.Add(-1 * time.Hour)

	// 150 entries inside the window (old code exported only 100 of them)
	// plus 50 older entries that must survive the rotate.
	for i := 0; i < 150; i++ {
		insertEntry(t, log, recent, "redacted")
	}
	for i := 0; i < 50; i++ {
		insertEntry(t, log, old, "public")
	}

	since := now.Add(-24 * time.Hour)
	exportPath := filepath.Join(t.TempDir(), "rotate.json")
	count, err := log.Rotate(exportPath, since)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if count != 150 {
		t.Fatalf("rotated %d entries, want 150 (the full window — export must not be capped)", count)
	}

	// The 50 old entries must still be in the DB.
	remaining, err := log.Query("", time.Time{}, 10000)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(remaining) != 50 {
		t.Errorf("%d entries remain after rotate, want 50 (older-than-window entries must survive)", len(remaining))
	}
	for _, e := range remaining {
		if e.Timestamp.After(since) {
			t.Errorf("entry at %v survived despite being inside the rotate window", e.Timestamp)
		}
	}

	// And the export file must contain the 150 rotated entries.
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("reading export: %v", err)
	}
	var exported []Entry
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatalf("parsing export: %v", err)
	}
	if len(exported) != 150 {
		t.Errorf("export contains %d entries, want 150", len(exported))
	}
}

// Export must not be capped at 100 rows.
func TestExportUncapped(t *testing.T) {
	log := newTestLog(t)

	ts := time.Now().Add(-time.Minute)
	for i := 0; i < 250; i++ {
		insertEntry(t, log, ts, "redacted")
	}

	path := filepath.Join(t.TempDir(), "export.json")
	count, err := log.Export(path, time.Time{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if count != 250 {
		t.Errorf("exported %d entries, want 250 — export must not be capped", count)
	}
}

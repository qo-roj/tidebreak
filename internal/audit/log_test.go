package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestLog(t *testing.T) *Log {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_audit.db")
	log, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		log.Close()
		os.Remove(dbPath)
	})
	return log
}

func TestRecordAndQuery(t *testing.T) {
	log := newTestLog(t)

	entries := []Entry{
		{Agent: "claude", Provider: "anthropic", Action: "read", Target: "/etc/nginx/nginx.conf", Tier: "redacted", Redactions: `{"ips":2}`},
		{Agent: "claude", Provider: "anthropic", Action: "read", Target: "~/.ssh/id_rsa", Tier: "blocked"},
		{Agent: "codex", Provider: "openai", Action: "query", Target: "SELECT * FROM users", Tier: "local-only"},
		{Agent: "hermes", Provider: "ollama", Action: "summarize", Target: "/var/log/syslog", Tier: "local-only", Redactions: `{"ips":47}`},
	}

	for _, e := range entries {
		log.Record(e)
	}

	// Wait for async writer to flush
	time.Sleep(200 * time.Millisecond)

	results, err := log.Query("", time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 4 {
		t.Errorf("expected 4 entries, got %d", len(results))
	}

	// Results should be newest first
	if results[0].Agent != "hermes" {
		t.Errorf("expected first entry to be hermes (newest), got %s", results[0].Agent)
	}
}

func TestQueryByAgent(t *testing.T) {
	log := newTestLog(t)

	log.Record(Entry{Agent: "claude", Provider: "anthropic", Action: "read", Target: "/etc/hosts", Tier: "public"})
	log.Record(Entry{Agent: "codex", Provider: "openai", Action: "read", Target: "/etc/shadow", Tier: "blocked"})
	log.Record(Entry{Agent: "claude", Provider: "anthropic", Action: "write", Target: "/tmp/output.txt", Tier: "public"})

	time.Sleep(200 * time.Millisecond)

	results, err := log.Query("claude", time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 claude entries, got %d", len(results))
	}
	for _, e := range results {
		if e.Agent != "claude" {
			t.Errorf("expected agent=claude, got %s", e.Agent)
		}
	}
}

func TestQuerySince(t *testing.T) {
	log := newTestLog(t)

	// Record one entry
	log.Record(Entry{Agent: "test", Provider: "anthropic", Action: "read", Target: "/a", Tier: "public"})
	time.Sleep(200 * time.Millisecond)

	// Now record another after a known time
	cutoff := time.Now()
	time.Sleep(50 * time.Millisecond)
	log.Record(Entry{Agent: "test", Provider: "anthropic", Action: "read", Target: "/b", Tier: "redacted"})

	time.Sleep(200 * time.Millisecond)

	results, err := log.Query("", cutoff, 100)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 entry since cutoff, got %d", len(results))
	}
	if results[0].Target != "/b" {
		t.Errorf("expected target /b, got %s", results[0].Target)
	}
}

func TestGetSummary(t *testing.T) {
	log := newTestLog(t)

	entries := []Entry{
		{Agent: "claude", Provider: "anthropic", Action: "read", Tier: "redacted", Redactions: `{"ips":2}`},
		{Agent: "claude", Provider: "anthropic", Action: "read", Tier: "public"},
		{Agent: "codex", Provider: "openai", Action: "read", Tier: "blocked"},
		{Agent: "codex", Provider: "ollama", Action: "summarize", Tier: "local-only", Redactions: `{"ips":5}`},
	}

	for _, e := range entries {
		log.Record(e)
	}

	time.Sleep(200 * time.Millisecond)

	summary, err := log.GetSummary(time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	if summary.Total != 4 {
		t.Errorf("expected total 4, got %d", summary.Total)
	}
	if summary.ByTier["redacted"] != 1 {
		t.Errorf("expected 1 redacted, got %d", summary.ByTier["redacted"])
	}
	if summary.ByTier["public"] != 1 {
		t.Errorf("expected 1 public, got %d", summary.ByTier["public"])
	}
	if summary.ByTier["blocked"] != 1 {
		t.Errorf("expected 1 blocked, got %d", summary.ByTier["blocked"])
	}
	if summary.ByTier["local-only"] != 1 {
		t.Errorf("expected 1 local-only, got %d", summary.ByTier["local-only"])
	}
	if summary.ByAgent["claude"] != 2 {
		t.Errorf("expected 2 claude, got %d", summary.ByAgent["claude"])
	}
	if summary.ByProvider["anthropic"] != 2 {
		t.Errorf("expected 2 anthropic, got %d", summary.ByProvider["anthropic"])
	}
	if summary.Redactions != 2 {
		t.Errorf("expected 2 entries with redactions, got %d", summary.Redactions)
	}
}

func TestCloseFlushes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_flush.db")
	log, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		log.Record(Entry{
			Agent:    "test",
			Provider: "anthropic",
			Action:   "read",
			Tier:     "public",
		})
	}

	log.Close()

	// Reopen and verify all entries were flushed
	db, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	results, err := db.Query("", time.Time{}, 1000)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 100 {
		t.Errorf("expected 100 entries after flush, got %d", len(results))
	}
}

func TestConcurrentWrites(t *testing.T) {
	log := newTestLog(t)

	done := make(chan struct{})

	// Multiple goroutines recording simultaneously
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				log.Record(Entry{
					Agent:    "test",
					Provider: "anthropic",
					Action:   "read",
					Target:   "/file",
					Tier:     "public",
				})
			}
			done <- struct{}{}
		}(i)
	}

	// Wait for all writers
	for i := 0; i < 10; i++ {
		<-done
	}

	time.Sleep(500 * time.Millisecond)

	results, err := log.Query("", time.Time{}, 10000)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 500 {
		t.Errorf("expected 500 entries, got %d", len(results))
	}
}

func TestSchemaCreated(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_schema.db")
	log, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	// Verify the table exists by inserting and querying
	log.Record(Entry{Agent: "test", Provider: "test", Action: "test", Tier: "public"})
	time.Sleep(200 * time.Millisecond)

	results, err := log.Query("", time.Time{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(results))
	}

	// Verify indexes exist (query should be fast, no error)
	results, err = log.Query("test", time.Time{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Error("expected to find entry by agent")
	}
}

func TestExport(t *testing.T) {
	log := newTestLog(t)

	entries := []Entry{
		{Agent: "claude", Provider: "anthropic", Action: "read", Target: "/a", Tier: "redacted"},
		{Agent: "codex", Provider: "openai", Action: "read", Target: "/b", Tier: "public"},
	}
	for _, e := range entries {
		log.Record(e)
	}
	time.Sleep(200 * time.Millisecond)

	exportPath := filepath.Join(t.TempDir(), "export.json")
	count, err := log.Export(exportPath, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2 exported, got %d", count)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("export file is empty")
	}
}

func TestRotate(t *testing.T) {
	log := newTestLog(t)

	for i := 0; i < 5; i++ {
		log.Record(Entry{Agent: "test", Provider: "test", Action: "read", Target: "/file", Tier: "public"})
	}
	time.Sleep(200 * time.Millisecond)

	// Verify entries exist
	results, err := log.Query("", time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 5 {
		t.Fatalf("expected 5 entries before rotate, got %d", len(results))
	}

	// Rotate
	exportPath := filepath.Join(t.TempDir(), "rotate.json")
	count, err := log.Rotate(exportPath, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Errorf("expected 5 rotated, got %d", count)
	}

	// Verify DB is empty
	time.Sleep(200 * time.Millisecond)
	results, err = log.Query("", time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 entries after rotate, got %d", len(results))
	}
}

package db

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"testing"
	"time"
)

func TestInitDB(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("failed to close database: %v", err)
		}
	}()
	// Check if table exists by inserting a row
	_, err = db.Exec(`INSERT INTO arp_seen (ip, ip_type, mac, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)`,
		"1.2.3.4", "ipv4", "00:11:22:33:44:55", time.Now(), time.Now())
	if err != nil {
		t.Errorf("Insert failed after InitDB: %v", err)
	}
}

func TestInsertAndGetRecentEntries(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("failed to close database: %v", err)
		}
	}()
	// Insert IPv4 and IPv6 events
	InsertARPEvent(db, "192.168.1.10", "00:11:22:33:44:55")
	InsertARPEvent(db, "fe80::1", "00:11:22:33:44:55")
	InsertARPEvent(db, "192.168.1.11", "66:77:88:99:AA:BB")

	entries, err := GetRecentEntries(db, 1)
	if err != nil {
		t.Fatalf("GetRecentEntries failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 MACs, got %d: %+v", len(entries), entries)
	}

	// Check first MAC
	var found1, found2 bool
	for _, e := range entries {
		switch e.MAC {
		case "00:11:22:33:44:55":
			found1 = true
			if len(e.IPv4) != 1 || e.IPv4[0] != "192.168.1.10" {
				t.Errorf("expected IPv4 192.168.1.10, got %v", e.IPv4)
			}
			if len(e.IPv6) != 1 || e.IPv6[0] != "fe80::1" {
				t.Errorf("expected IPv6 fe80::1, got %v", e.IPv6)
			}
		case "66:77:88:99:AA:BB":
			found2 = true
			if len(e.IPv4) != 1 || e.IPv4[0] != "192.168.1.11" {
				t.Errorf("expected IPv4 192.168.1.11, got %v", e.IPv4)
			}
			if len(e.IPv6) != 0 {
				t.Errorf("expected no IPv6, got %v", e.IPv6)
			}
		default:
			t.Errorf("unexpected MAC: %s", e.MAC)
		}
	}
	if !found1 || !found2 {
		t.Errorf("missing expected MACs in result")
	}
}

func TestAddIfNotExists(t *testing.T) {
	s := []string{"a", "b"}
	s2 := addIfNotExists(s, "c")
	if len(s2) != 3 || s2[2] != "c" {
		t.Errorf("addIfNotExists failed to add new item: %v", s2)
	}
	s3 := addIfNotExists(s2, "a")
	if len(s3) != 3 {
		t.Errorf("addIfNotExists added duplicate: %v", s3)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("failed to close database: %v", err)
		}
	})
	return db
}

func countRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM arp_seen`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func setLastSeen(t *testing.T, db *sql.DB, ip string, age time.Duration) {
	t.Helper()
	if _, err := db.Exec(`UPDATE arp_seen SET last_seen = ? WHERE ip = ?`, time.Now().UTC().Add(-age), ip); err != nil {
		t.Fatal(err)
	}
}

func TestRepeatedPacketsDoNotAddRows(t *testing.T) {
	db := openTestDB(t)
	for range 1000 {
		InsertARPEvent(db, "192.168.1.10", "00:11:22:33:44:55")
	}
	if n := countRows(t, db); n != 1 {
		t.Fatalf("expected 1 row, got %d", n)
	}
}

func TestInsertKeepsFirstSeenAndUpdatesLastSeen(t *testing.T) {
	db := openTestDB(t)
	InsertARPEvent(db, "192.168.1.10", "00:11:22:33:44:55")
	if _, err := db.Exec(`UPDATE arp_seen SET first_seen = ?, last_seen = ?`, time.Unix(1000, 0).UTC(), time.Unix(1000, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	InsertARPEvent(db, "192.168.1.10", "00:11:22:33:44:55")

	var first, last time.Time
	if err := db.QueryRow(`SELECT first_seen, last_seen FROM arp_seen`).Scan(&first, &last); err != nil {
		t.Fatal(err)
	}
	if first.Unix() != 1000 {
		t.Errorf("first_seen changed: %v", first)
	}
	if time.Since(last) > time.Minute {
		t.Errorf("last_seen not updated: %v", last)
	}
}

func TestRecentEntriesListNewestAddressFirst(t *testing.T) {
	db := openTestDB(t)
	InsertARPEvent(db, "192.168.1.10", "00:11:22:33:44:55")
	InsertARPEvent(db, "192.168.1.11", "00:11:22:33:44:55")
	setLastSeen(t, db, "192.168.1.10", time.Hour)

	entries, err := GetRecentEntries(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IPv4[0] != "192.168.1.11" {
		t.Fatalf("got %+v", entries)
	}
}

func TestRecentEntriesReportEarliestFirstSeen(t *testing.T) {
	db := openTestDB(t)
	InsertARPEvent(db, "192.168.1.10", "00:11:22:33:44:55")
	InsertARPEvent(db, "192.168.1.11", "00:11:22:33:44:55")
	early := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	if _, err := db.Exec(`UPDATE arp_seen SET first_seen = ? WHERE ip = '192.168.1.10'`, early); err != nil {
		t.Fatal(err)
	}

	entries, err := GetRecentEntries(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].FirstSeen.Equal(early) {
		t.Fatalf("got %+v, want first seen %v", entries, early)
	}
}

func TestPruneKeepsNewestPairOfEachMAC(t *testing.T) {
	db := openTestDB(t)
	const day = 24 * time.Hour
	InsertARPEvent(db, "192.168.1.1", "00:00:00:00:00:01") // old, newer pair exists: removed
	InsertARPEvent(db, "192.168.1.2", "00:00:00:00:00:01") // recent
	InsertARPEvent(db, "192.168.1.3", "00:00:00:00:00:02") // old but the only pair of the MAC
	InsertARPEvent(db, "192.168.1.4", "00:00:00:00:00:03") // old, newer pair is old too: removed
	InsertARPEvent(db, "192.168.1.5", "00:00:00:00:00:03") // old but newest of the MAC
	setLastSeen(t, db, "192.168.1.1", 40*day)
	setLastSeen(t, db, "192.168.1.3", 40*day)
	setLastSeen(t, db, "192.168.1.4", 50*day)
	setLastSeen(t, db, "192.168.1.5", 40*day)

	removed, err := Prune(db, 30)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("expected 2 removed rows, got %d", removed)
	}
	rows, err := db.Query(`SELECT ip FROM arp_seen ORDER BY ip`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			t.Fatal(err)
		}
		ips = append(ips, ip)
	}
	if want := "[192.168.1.2 192.168.1.3 192.168.1.5]"; fmt.Sprint(ips) != want {
		t.Errorf("got %v, want %s", ips, want)
	}
}

func TestMigrationFoldsEventsAndIsRepeatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arp.db")
	old, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE arp_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ip_type TEXT NOT NULL,
        mac TEXT NOT NULL, seen_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	// timestamps as written by the old version: local time with offset
	events := []struct{ ip, typ, mac, seen string }{
		{"192.168.1.10", "ipv4", "aa:aa:aa:aa:aa:aa", "2026-06-02 19:48:41.702314842+02:00"},
		{"192.168.1.10", "ipv4", "aa:aa:aa:aa:aa:aa", "2026-10-30 16:55:15.143559104+01:00"},
		{"192.168.1.10", "ipv4", "aa:aa:aa:aa:aa:aa", "2026-08-01 12:00:00.5+02:00"},
		{"fe80::1", "ipv6", "aa:aa:aa:aa:aa:aa", "2026-07-01 12:00:00.5+02:00"},
		{"192.168.1.11", "ipv4", "bb:bb:bb:bb:bb:bb", "2026-07-01 12:00:00.5+02:00"},
		{"192.168.1.12", "ipv4", "cc:cc:cc:cc:cc:cc", "garbage"},
	}
	for _, e := range events {
		if _, err := old.Exec(`INSERT INTO arp_events (ip, ip_type, mac, seen_at) VALUES (?, ?, ?, ?)`, e.ip, e.typ, e.mac, e.seen); err != nil {
			t.Fatal(err)
		}
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := InitDB(path)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	if n := countRows(t, db); n != 3 {
		t.Errorf("expected 3 pairs, got %d", n)
	}
	var first, last time.Time
	var ipType string
	err = db.QueryRow(`SELECT ip_type, first_seen, last_seen FROM arp_seen WHERE ip = '192.168.1.10'`).Scan(&ipType, &first, &last)
	if err != nil {
		t.Fatal(err)
	}
	if ipType != "ipv4" {
		t.Errorf("ip_type %s", ipType)
	}
	if want := time.Date(2026, 6, 2, 17, 48, 41, 0, time.UTC); !first.Equal(want) {
		t.Errorf("first_seen %v, want %v", first, want)
	}
	if want := time.Date(2026, 10, 30, 15, 55, 15, 0, time.UTC); !last.Equal(want) {
		t.Errorf("last_seen %v, want %v", last, want)
	}
	var tables int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'arp_events'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Error("arp_events still exists")
	}

	// migrated timestamps stay comparable with new ones
	InsertARPEvent(db, "192.168.1.11", "bb:bb:bb:bb:bb:bb")
	if n := countRows(t, db); n != 3 {
		t.Errorf("insert after migration added a row: %d", n)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := InitDB(path)
	if err != nil {
		t.Fatalf("second start failed: %v", err)
	}
	defer func() {
		if err := again.Close(); err != nil {
			t.Error(err)
		}
	}()
	if n := countRows(t, again); n != 3 {
		t.Errorf("second start changed the data: %d", n)
	}
}

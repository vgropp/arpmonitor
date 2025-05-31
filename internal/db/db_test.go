package db

import (
	"log"
	"testing"
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
	_, err = db.Exec(`INSERT INTO arp_events (ip, ip_type, mac) VALUES (?, ?, ?)`, "1.2.3.4", "ipv4", "00:11:22:33:44:55")
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

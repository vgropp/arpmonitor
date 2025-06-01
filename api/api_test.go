package api

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vgropp/arpmonitor/internal/db"
)

// --- firstMatchOrEmpty tests ---

func TestFirstMatchOrEmpty(t *testing.T) {
	tests := []struct {
		name    string
		slice   []string
		pattern string
		want    string
	}{
		{"empty slice", []string{}, "", ""},
		{"no match, return first", []string{"a", "b"}, "x", "a"},
		{"match at start", []string{"foo", "bar"}, "f", "foo"},
		{"match not at start", []string{"bar", "foo"}, "f", "foo"},
		{"multiple matches", []string{"fa", "fb", "c"}, "f", "fa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstMatchOrEmpty(tt.slice, tt.pattern)
			if got != tt.want {
				t.Errorf("firstMatchOrEmpty() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- lookupEntry tests ---

func TestLookupEntry(t *testing.T) {
	// Save original net.LookupAddr and restore after test
	origLookupAddr := netLookupAddr
	defer func() { netLookupAddr = origLookupAddr }()

	// Mock net.LookupAddr
	type lookupCall struct {
		addr string
		ret  []string
		err  error
	}
	calls := []lookupCall{
		{"1.2.3.4", []string{"host1.local."}, nil},
		{"fe80::1", []string{"host6.local."}, nil},
	}
	callIdx := 0
	netLookupAddr = func(addr string) ([]string, error) {
		if callIdx >= len(calls) {
			return nil, nil
		}
		c := calls[callIdx]
		callIdx++
		if c.addr != addr {
			t.Errorf("lookup called with %q, want %q", addr, c.addr)
		}
		return c.ret, c.err
	}

	entry := db.ArpEntry{
		MAC:      "00:11:22:33:44:55",
		Hostname: "",
		IPv4:     []string{"1.2.3.4"},
		IPv6:     []string{"fe80::1"},
	}

	lookupEntry(&entry, false, "")
	if entry.Hostname != "host1.local." {
		t.Errorf("lookupEntry() Hostname = %q, want %q", entry.Hostname, "host1.local.")
	}

	// Now test with resolveIpv6 true and IPv4 lookup fails
	callIdx = 0
	calls = []lookupCall{
		{"1.2.3.4", nil, assertErr{}},
		{"fe80::1", []string{"host6.local."}, nil},
	}
	entry = db.ArpEntry{
		MAC:      "00:11:22:33:44:55",
		Hostname: "",
		IPv4:     []string{"1.2.3.4"},
		IPv6:     []string{"fe80::1"},
	}
	lookupEntry(&entry, true, "")
	if entry.Hostname != "host6.local." {
		t.Errorf("lookupEntry() Hostname = %q, want %q", entry.Hostname, "host6.local.")
	}
}

var mockLookupAddr func(addr string) ([]string, error)

func TestLookupEntryFunc_IPv4(t *testing.T) {
	entry := db.ArpEntry{
		IPv4: []string{"1.2.3.4"},
	}
	mockLookupAddr = func(addr string) ([]string, error) {
		if addr == "1.2.3.4" {
			return []string{"host4.local."}, nil
		}
		return nil, nil
	}
	lookupEntryFunc(&entry, false, "")
	if entry.Hostname != "host4.local." {
		t.Errorf("expected host4.local., got %q", entry.Hostname)
	}
}

func TestLookupEntryFunc_IPv6(t *testing.T) {
	entry := db.ArpEntry{
		IPv4: []string{"0.0.0.0"},
		IPv6: []string{"fe80::1"},
	}
	callCount := 0
	mockLookupAddr = func(addr string) ([]string, error) {
		callCount++
		if addr == "0.0.0.0" {
			return nil, assertErr{}
		}
		if addr == "fe80::1" {
			return []string{"host6.local."}, nil
		}
		return nil, nil
	}
	lookupEntryFunc(&entry, true, "")
	if entry.Hostname != "host6.local." {
		t.Errorf("expected host6.local., got %q", entry.Hostname)
	}
	if callCount != 2 {
		t.Errorf("expected 2 lookups, got %d", callCount)
	}
}

// --- helpers for mocking net.LookupAddr ---

type assertErr struct{}

func (assertErr) Error() string { return "mock error" }

// Patch lookupEntry to use netLookupAddr for testability
func init() {
	lookupEntry = func(entry *db.ArpEntry, resolveIpv6 bool, preferIpv4Net string) {
		names, err := netLookupAddr(firstMatchOrEmpty(entry.IPv4, preferIpv4Net))
		if err == nil && len(names) > 0 {
			entry.Hostname = names[0]
		} else if resolveIpv6 {
			names, err = netLookupAddr(firstMatchOrEmpty(entry.IPv6, ""))
			if err == nil && len(names) > 0 {
				entry.Hostname = names[0]
			}
		}
	}
	netLookupAddr = func(addr string) ([]string, error) {
		return mockLookupAddr(addr)
	}
}

var testEntries = []db.ArpEntry{
	{
		MAC:      "00:11:22:33:44:55",
		Hostname: "host1",
		IPv4:     []string{"192.168.1.10"},
		IPv6:     []string{"fe80::1"},
	},
	{
		MAC:      "66:77:88:99:AA:BB",
		Hostname: "host2",
		IPv4:     []string{"192.168.1.11"},
		IPv6:     []string{},
	},
}

func setupTestAPI() (func(), string) {
	origGetRecentEntries := getRecentEntries
	getRecentEntries = func(database *sql.DB, days int) ([]db.ArpEntry, error) {
		return testEntries, nil
	}
	origLookupEntry := lookupEntry
	lookupEntry = func(entry *db.ArpEntry, resolveIpv6 bool, preferIpv4Net string) {}

	mux := http.NewServeMux()
	RegisterHandlers(mux, nil, false, "", false)
	server := httptest.NewServer(mux)

	// Save server for cleanup
	cleanup := func() {
		getRecentEntries = origGetRecentEntries
		lookupEntry = origLookupEntry
		server.Close()
	}
	// Return cleanup and server URL
	return cleanup, server.URL
}

func TestAPI_CurrentEndpoint(t *testing.T) {
	cleanup, url := setupTestAPI()
	defer cleanup()
	server := httptest.NewServer(http.DefaultServeMux)
	defer server.Close()

	resp, err := http.Get(url + "/api/current")
	if err != nil {
		t.Fatalf("GET /api/current failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/current status = %d, want 200", resp.StatusCode)
	}
	var gotEntries []db.ArpEntry
	if err := json.NewDecoder(resp.Body).Decode(&gotEntries); err != nil {
		t.Fatalf("decode /api/current: %v", err)
	}
	if len(gotEntries) != len(testEntries) {
		t.Errorf("got %d entries, want %d", len(gotEntries), len(testEntries))
	}
	for i, e := range gotEntries {
		if e.MAC != testEntries[i].MAC || e.Hostname != testEntries[i].Hostname {
			t.Errorf("entry %d: got %+v, want %+v", i, e, testEntries[i])
		}
	}
}

func TestAPI_EthersEndpoint(t *testing.T) {
	cleanup, url := setupTestAPI()
	defer cleanup()
	server := httptest.NewServer(http.DefaultServeMux)
	defer server.Close()

	resp, err := http.Get(url + "/api/ethers")
	if err != nil {
		t.Fatalf("GET /api/ethers failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ethers status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 3 {
		t.Errorf("expected at least 3 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[1], "00:11:22:33:44:55") || !strings.Contains(lines[2], "66:77:88:99:AA:BB") {
		t.Errorf("output missing expected MAC addresses: %q", lines)
	}
}

func TestStartAPI(t *testing.T) {
	called := false
	ListenAndServe = func(addr string, handler http.Handler) error {
		called = true
		// Optionally call handler directly or just return nil
		return nil
	}
	defer func() { ListenAndServe = http.ListenAndServe }() // reset after test

	database, _ := sql.Open("sqlite3", ":memory:")
	if err := db.CreateTable(database); err != nil {
		log.Fatalf("failed to create table: %v", err)
	}
	mux := StartAPI(8080, database, false, "", false)
	testServer := httptest.NewServer(mux)

	resp, err := http.Get(testServer.URL + "/api/current")
	if err != nil {
		t.Fatalf("Failed to GET: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("failed to close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if !called {
		t.Errorf("expected Serve to be called")
	}

	resp, err = http.Get(testServer.URL + "/api/ethers")
	if err != nil {
		t.Fatalf("Failed to GET: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("failed to close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if !called {
		t.Errorf("expected Serve to be called")
	}

}

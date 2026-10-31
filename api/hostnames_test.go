package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vgropp/arpmonitor/internal/db"
)

type fakeResolver struct {
	calls atomic.Int32
	mu    sync.Mutex
	name  string
}

func (r *fakeResolver) resolve(entry *db.ArpEntry, _ bool, _ string, _ bool) {
	r.calls.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	entry.Hostname = r.name
}

func device(ip string) *db.ArpEntry {
	return &db.ArpEntry{MAC: "00:11:22:33:44:55", IPv4: []string{ip}}
}

func TestHostnameCacheResolvesOnce(t *testing.T) {
	r := &fakeResolver{name: "nas."}
	c := newHostnameCache(r.resolve)
	for range 3 {
		e := device("192.168.1.10")
		c.lookup(e, false, "", false)
		if e.Hostname != "nas." {
			t.Fatalf("hostname %q", e.Hostname)
		}
	}
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("%d lookups", n)
	}
}

func TestHostnameCacheRemembersMissingNames(t *testing.T) {
	r := &fakeResolver{}
	c := newHostnameCache(r.resolve)
	c.lookup(device("192.168.1.10"), false, "", false)
	c.lookup(device("192.168.1.10"), false, "", false)
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("%d lookups", n)
	}
}

func TestHostnameCacheSeparatesAddresses(t *testing.T) {
	r := &fakeResolver{name: "nas."}
	c := newHostnameCache(r.resolve)
	c.lookup(device("192.168.1.10"), false, "", false)
	c.lookup(device("192.168.1.11"), false, "", false)
	if n := r.calls.Load(); n != 2 {
		t.Fatalf("%d lookups", n)
	}
}

func TestHostnameCacheServesOldNameWhileRefreshing(t *testing.T) {
	r := &fakeResolver{name: "old."}
	c := newHostnameCache(r.resolve)
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	c.now = func() time.Time { return time.Unix(0, now.Load()) }
	c.lookup(device("192.168.1.10"), false, "", false)

	r.mu.Lock()
	r.name = "new."
	now.Add(int64(2 * hostnameTTL))
	e := device("192.168.1.10")
	c.lookup(e, false, "", false) // the resolver is blocked, this must not wait for it
	c.lookup(device("192.168.1.10"), false, "", false)
	if e.Hostname != "old." {
		t.Errorf("hostname %q", e.Hostname)
	}
	r.mu.Unlock()

	for i := 0; i < 100; i++ {
		e = device("192.168.1.10")
		c.lookup(e, false, "", false)
		if e.Hostname == "new." {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.Hostname != "new." {
		t.Errorf("name not renewed: %q", e.Hostname)
	}
	if n := r.calls.Load(); n != 2 {
		t.Errorf("%d lookups", n)
	}
}

func TestLookupEntriesAreCachedByDefault(t *testing.T) {
	var calls atomic.Int32
	c := newHostnameCache(func(entry *db.ArpEntry, _ bool, _ string, _ bool) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
	})
	var wg sync.WaitGroup
	start := time.Now()
	c.lookup(device("192.168.1.10"), false, "", false)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.lookup(device("192.168.1.10"), false, "", false)
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("cached lookups took %v", elapsed)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("%d lookups", n)
	}
}

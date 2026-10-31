package api

import (
	"sync"
	"time"

	"github.com/vgropp/arpmonitor/internal/db"
)

// hostnameTTL is how long a resolved name counts as fresh.
const hostnameTTL = 5 * time.Minute

type lookupFunc func(entry *db.ArpEntry, resolveIpv6 bool, preferIpv4Net string, resolveKeaLeases bool)

type cachedHostname struct {
	hostname   string
	fetched    time.Time
	refreshing bool
}

// hostnameCache remembers the result of name lookups per device, also when there
// is no name: every lookup costs a DNS query and may read the Kea lease files.
// An outdated name is still returned and renewed in the background, so that only
// the first query for a device has to wait.
type hostnameCache struct {
	resolve lookupFunc
	ttl     time.Duration
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]*cachedHostname
}

func newHostnameCache(resolve lookupFunc) *hostnameCache {
	return &hostnameCache{resolve: resolve, ttl: hostnameTTL, now: time.Now, entries: map[string]*cachedHostname{}}
}

func (c *hostnameCache) lookup(entry *db.ArpEntry, resolveIpv6 bool, preferIpv4Net string, resolveKeaLeases bool) {
	key := entry.MAC + "|" + firstMatchOrEmpty(entry.IPv4, preferIpv4Net)
	refresh := func(device db.ArpEntry) string {
		c.resolve(&device, resolveIpv6, preferIpv4Net, resolveKeaLeases)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.entries[key] = &cachedHostname{hostname: device.Hostname, fetched: c.now()}
		return device.Hostname
	}

	c.mu.Lock()
	cached, ok := c.entries[key]
	if ok && c.now().Sub(cached.fetched) >= c.ttl && !cached.refreshing {
		cached.refreshing = true
		go refresh(*entry)
	}
	if ok {
		entry.Hostname = cached.hostname
	}
	c.mu.Unlock()

	if !ok {
		entry.Hostname = refresh(*entry)
	}
}

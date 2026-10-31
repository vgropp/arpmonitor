package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const cleanupInterval = time.Hour

type ArpEntry struct {
	MAC       string    `json:"mac"`
	IPv4      []string  `json:"ipv4,omitempty"`
	IPv6      []string  `json:"ipv6,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func InitDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	// sniffer, API and cleanup share one connection instead of failing with
	// "database is locked"; it also keeps ":memory:" a single database.
	db.SetMaxOpenConns(1)

	if err := CreateTable(db); err != nil {
		return db, err
	}
	return db, migrateEvents(db)
}

// CreateTable keeps one row per MAC/IP pair, so the size of the table depends on
// the devices in the network and not on the number of packets.
func CreateTable(db *sql.DB) error {
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS arp_seen (
            mac TEXT NOT NULL,
            ip TEXT NOT NULL,
            ip_type TEXT NOT NULL,   -- 'ipv4' or 'ipv6'
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            PRIMARY KEY (mac, ip)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS arp_seen_last_seen ON arp_seen (last_seen);
    `)
	return err
}

// migrateEvents folds the old arp_events table, which held one row per packet,
// into arp_seen and returns the freed space to the file system. The move is one
// transaction, so an interrupted migration simply starts over on the next run.
func migrateEvents(db *sql.DB) error {
	var tables int
	err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'arp_events'`).Scan(&tables)
	if err != nil || tables == 0 {
		return err
	}

	log.Println("migrating arp_events to arp_seen, this can take a while")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Printf("rollback failed: %v", err)
		}
	}()
	// datetime() normalizes the local timestamps of arp_events to UTC.
	result, err := tx.Exec(`
        INSERT INTO arp_seen (mac, ip, ip_type, first_seen, last_seen)
        SELECT mac, ip, MAX(ip_type), MIN(datetime(seen_at)), MAX(datetime(seen_at))
        FROM arp_events
        WHERE datetime(seen_at) IS NOT NULL
        GROUP BY mac, ip
    `)
	if err != nil {
		return fmt.Errorf("migrate arp_events: %w", err)
	}
	if _, err := tx.Exec(`DROP TABLE arp_events`); err != nil {
		return fmt.Errorf("drop arp_events: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	log.Printf("migrated to %d MAC/IP pairs", rows)

	// The data is safe at this point, a failed VACUUM only keeps the file large.
	if _, err := db.Exec(`VACUUM`); err != nil {
		log.Printf("VACUUM failed: %v", err)
	}
	return nil
}

func InsertARPEvent(db *sql.DB, ip, mac string) {
	// Determine whether this is IPv4 or IPv6
	var ipType string
	if net.ParseIP(ip).To4() != nil {
		ipType = "ipv4"
	} else {
		ipType = "ipv6"
	}

	now := time.Now().UTC()
	_, err := db.Exec(`
        INSERT INTO arp_seen (mac, ip, ip_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (mac, ip) DO UPDATE SET last_seen = excluded.last_seen
    `, mac, ip, ipType, now, now)
	if err != nil {
		log.Println("DB error:", err)
	}
}

// Prune removes pairs not seen for the given number of days, except the newest
// pair of each MAC, so a known device is never forgotten completely. It returns
// the number of removed rows. Freed pages are reused by later inserts.
func Prune(db *sql.DB, days int) (int64, error) {
	result, err := db.Exec(`
        DELETE FROM arp_seen
        WHERE last_seen < datetime('now', ?)
          AND EXISTS (
            SELECT 1 FROM arp_seen AS newer
            WHERE newer.mac = arp_seen.mac AND newer.last_seen > arp_seen.last_seen
          )
    `, fmt.Sprintf("-%d days", days))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// StartCleanup prunes old pairs at once and then periodically. It never returns;
// days <= 0 turns the cleanup off.
func StartCleanup(db *sql.DB, days int) {
	if days <= 0 {
		return
	}
	for {
		if removed, err := Prune(db, days); err != nil {
			log.Printf("cleanup failed: %v", err)
		} else if removed > 0 {
			log.Printf("cleanup removed %d old entries", removed)
		}
		time.Sleep(cleanupInterval)
	}
}

func GetRecentEntries(db *sql.DB, days int) ([]ArpEntry, error) {
	rows, err := db.Query(`
        SELECT mac, ip, ip_type, first_seen, last_seen FROM arp_seen
        WHERE last_seen >= datetime('now', ?) order by mac,last_seen desc
        `, fmt.Sprintf("-%d days", days))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("error closing rows: %v", err)
		}
	}()

	macMap := make(map[string]*ArpEntry)

	for rows.Next() {
		var mac, ip, ipType string
		var firstSeen, seenAt time.Time
		if err := rows.Scan(&mac, &ip, &ipType, &firstSeen, &seenAt); err != nil {
			continue
		}

		entry, exists := macMap[mac]
		if !exists {
			entry = &ArpEntry{
				MAC: mac,
			}
			macMap[mac] = entry
		}

		switch ipType {
		case "ipv4":
			entry.IPv4 = addIfNotExists(entry.IPv4, ip)
		case "ipv6":
			entry.IPv6 = addIfNotExists(entry.IPv6, ip)
		}

		if seenAt.After(entry.LastSeen) {
			entry.LastSeen = seenAt
		}
		if entry.FirstSeen.IsZero() || firstSeen.Before(entry.FirstSeen) {
			entry.FirstSeen = firstSeen
		}
	}

	var result []ArpEntry
	for _, entry := range macMap {
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].MAC < result[j].MAC
	})

	return result, nil
}

func addIfNotExists[T comparable](slice []T, item T) []T {
	for _, v := range slice {
		if v == item {
			return slice // Already exists, return unchanged
		}
	}
	return append(slice, item)
}

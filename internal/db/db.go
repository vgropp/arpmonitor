package db

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type ArpEntry struct {
	MAC      string    `json:"mac"`
	IPv4     []string  `json:"ipv4,omitempty"`
	IPv6     []string  `json:"ipv6,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

func InitDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	err = CreateTable(db)
	return db, err
}

func CreateTable(db *sql.DB) error {
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS arp_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            ip_type TEXT NOT NULL,   -- 'ipv4' or 'ipv6'
            mac TEXT NOT NULL,
            seen_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `)
	return err
}

func InsertARPEvent(db *sql.DB, ip, mac string) {
	// Bestimmen, ob es sich um IPv4 oder IPv6 handelt
	var ipType string
	if net.ParseIP(ip).To4() != nil {
		ipType = "ipv4"
	} else {
		ipType = "ipv6"
	}

	_, err := db.Exec(`INSERT INTO arp_events (ip, ip_type, mac, seen_at) VALUES (?, ?, ?, ?)`,
		ip, ipType, mac, time.Now())
	if err != nil {
		log.Println("DB Fehler:", err)
	}
}

func GetRecentEntries(db *sql.DB, days int) ([]ArpEntry, error) {
	rows, err := db.Query(`
        SELECT mac, ip, ip_type, seen_at FROM arp_events
        WHERE seen_at >= datetime('now', ?) order by mac,seen_at desc
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
		var seenAt time.Time
		if err := rows.Scan(&mac, &ip, &ipType, &seenAt); err != nil {
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

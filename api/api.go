package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/vgropp/arpmonitor/internal/db"
)

const IPV4_PREFERED = "192.168."

func StartAPI(port int, database *sql.DB, resolveIpv6 bool) {
	http.HandleFunc("/api/current", func(w http.ResponseWriter, r *http.Request) {
		daysStr := r.URL.Query().Get("days")
		days := 7
		if daysStr != "" {
			if parsed, err := strconv.Atoi(daysStr); err == nil {
				days = parsed
			}
		}

		entries, err := db.GetRecentEntries(database, days)
		if err != nil {
			http.Error(w, "error on reading entries", http.StatusInternalServerError)
			return
		}

		for _, entry := range entries {
			lookupEntry(&entry, resolveIpv6)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})

	http.HandleFunc("/api/ethers", func(w http.ResponseWriter, r *http.Request) {
		daysStr := r.URL.Query().Get("days")
		days := 7
		if daysStr != "" {
			if parsed, err := strconv.Atoi(daysStr); err == nil {
				days = parsed
			}
		}

		entries, err := db.GetRecentEntries(database, days)
		if err != nil {
			http.Error(w, "error on reading entries", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("# MAC-Adresse          Hostname             IPv4-Adresse      IPv6-Adresse\n"))

		for _, entry := range entries {

			lookupEntry(&entry, resolveIpv6)

			fmt.Fprintf(w, "%-20s %-20s %-15s %-15s\n", entry.MAC, entry.Hostname, firstMatchOrEmpty(entry.IPv4, IPV4_PREFERED), firstMatchOrEmpty(entry.IPv6, ""))
		}
	})

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("API verfügbar unter http://localhost%s/api/current\n", addr)
	http.ListenAndServe(addr, nil)
}

/** first or prefered network */
func firstMatchOrEmpty(slice []string, pattern string) string {
	for _, s := range slice {
		if strings.Contains(s, pattern) {
			return s
		}
	}
	if len(slice) > 0 {
		return slice[0]
	}
	return ""
}

func lookupEntry(entry *db.ArpEntry, resolveIpv6 bool) {
	names, err := net.LookupAddr(firstMatchOrEmpty(entry.IPv4, IPV4_PREFERED))
	if err == nil && len(names) > 0 {
		entry.Hostname = names[0]
	} else if resolveIpv6 {
		names, err = net.LookupAddr(firstMatchOrEmpty(entry.IPv6, ""))
		if err == nil && len(names) > 0 {
			entry.Hostname = names[0]
		}
	}
}

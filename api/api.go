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

func StartAPI(port int, database *sql.DB, resolveIpv6 bool, preferIpv4Net string, filterZeroIps bool) {
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
			lookupEntry(&entry, resolveIpv6, preferIpv4Net)
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
		w.Write([]byte("# MAC-Address          Hostname             IPv4-Address      IPv6-Address\n"))

		for _, entry := range entries {

			lookupEntry(&entry, resolveIpv6, preferIpv4Net)

			ipv4 := firstMatchOrEmpty(entry.IPv4, preferIpv4Net)
			if filterZeroIps && ipv4 == "0.0.0.0" && len(entry.IPv6) == 0 {
				continue
			}
			fmt.Fprintf(w, "%-20s %-20s %-15s %-15s\n", entry.MAC, entry.Hostname,
				ipv4,
				firstMatchOrEmpty(entry.IPv6, ""))
		}
	})

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("API: http://localhost%s/api/current\n", addr)
	http.ListenAndServe(addr, nil)
}

/** first or prefered network */
func firstMatchOrEmpty(slice []string, pattern string) string {
	for _, s := range slice {
		if strings.HasPrefix(s, pattern) {
			return s
		}
	}
	if len(slice) > 0 {
		return slice[0]
	}
	return ""
}

func lookupEntry(entry *db.ArpEntry, resolveIpv6 bool, preferIpv4Net string) {
	names, err := net.LookupAddr(firstMatchOrEmpty(entry.IPv4, preferIpv4Net))
	if err == nil && len(names) > 0 {
		entry.Hostname = names[0]
	} else if resolveIpv6 {
		names, err = net.LookupAddr(firstMatchOrEmpty(entry.IPv6, ""))
		if err == nil && len(names) > 0 {
			entry.Hostname = names[0]
		}
	}
}

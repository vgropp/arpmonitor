package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/vgropp/arpmonitor/internal/db"
)

var getRecentEntries = db.GetRecentEntries
var lookupEntry = lookupEntryFunc
var netLookupAddr = net.LookupAddr

func RegisterHandlers(mux *http.ServeMux, database *sql.DB, resolveIpv6 bool, preferIpv4Net string, filterZeroIps bool) {
	mux.HandleFunc("/api/current", func(w http.ResponseWriter, r *http.Request) {
		handleJson(r, database, w, resolveIpv6, preferIpv4Net)
	})
	mux.HandleFunc("/api/ethers", func(w http.ResponseWriter, r *http.Request) {
		handleEthers(r, database, w, resolveIpv6, preferIpv4Net, filterZeroIps)
	})
}

func handleEthers(r *http.Request, database *sql.DB, w http.ResponseWriter, resolveIpv6 bool, preferIpv4Net string, filterZeroIps bool) {
	daysStr := r.URL.Query().Get("days")
	days := 7
	if daysStr != "" {
		if parsed, err := strconv.Atoi(daysStr); err == nil {
			days = parsed
		}
	}

	entries, err := getRecentEntries(database, days)
	if err != nil {
		http.Error(w, "error on reading entries", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte("# MAC-Address          Hostname             IPv4-Address      IPv6-Address\n")); err != nil {
		http.Error(w, "error writing header", http.StatusInternalServerError)
		return
	}

	for _, entry := range entries {

		lookupEntry(&entry, resolveIpv6, preferIpv4Net)

		ipv4 := firstMatchOrEmpty(entry.IPv4, preferIpv4Net)
		if filterZeroIps && ipv4 == "0.0.0.0" && len(entry.IPv6) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "%-20s %-20s %-15s %-15s\n", entry.MAC, entry.Hostname,
			ipv4, firstMatchOrEmpty(entry.IPv6, "")); err != nil {
			http.Error(w, "error writing header", http.StatusInternalServerError)
			return
		}
	}
}

func handleJson(r *http.Request, database *sql.DB, w http.ResponseWriter, resolveIpv6 bool, preferIpv4Net string) {
	daysStr := r.URL.Query().Get("days")
	days := 7
	if daysStr != "" {
		if parsed, err := strconv.Atoi(daysStr); err == nil {
			days = parsed
		}
	}

	entries, err := getRecentEntries(database, days)
	if err != nil {
		http.Error(w, "error on reading entries", http.StatusInternalServerError)
		return
	}

	for _, entry := range entries {
		lookupEntry(&entry, resolveIpv6, preferIpv4Net)
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(entries); err != nil {
		http.Error(w, "internal server error, failed to encode JSON response", http.StatusInternalServerError)
	}
}

func StartAPI(port int, database *sql.DB, resolveIpv6 bool, preferIpv4Net string, filterZeroIps bool) {
	mux := http.NewServeMux()
	RegisterHandlers(mux, database, resolveIpv6, preferIpv4Net, filterZeroIps)
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("API: http://localhost%s/api/current\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
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

func lookupEntryFunc(entry *db.ArpEntry, resolveIpv6 bool, preferIpv4Net string) {
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

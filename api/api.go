package api

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/vgropp/arpmonitor/internal/db"
)

var getRecentEntries = db.GetRecentEntries
var lookupEntry = lookupEntryFunc
var netLookupAddr = net.LookupAddr

var leasesFiles = []string{
	"/var/lib/kea/kea-leases4.csv",
	"/var/lib/kea/kea-leases4.csv.2",
}

var ListenAndServe = func(addr string, handler http.Handler) error {
	return http.ListenAndServe(addr, handler)
}

func RegisterHandlers(mux *http.ServeMux, database *sql.DB, resolveIpv6 bool, preferIpv4Net string, filterZeroIps bool, resolveKeaLeases bool) {
	mux.HandleFunc("/api/current", func(w http.ResponseWriter, r *http.Request) {
		handleJson(r, database, w, resolveIpv6, preferIpv4Net, resolveKeaLeases)
	})
	mux.HandleFunc("/api/ethers", func(w http.ResponseWriter, r *http.Request) {
		handleEthers(r, database, w, resolveIpv6, preferIpv4Net, filterZeroIps, resolveKeaLeases)
	})
}

func handleEthers(r *http.Request, database *sql.DB, w http.ResponseWriter, resolveIpv6 bool, preferIpv4Net string, filterZeroIps bool, resolveKeaLeases bool) {
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

		lookupEntry(&entry, resolveIpv6, preferIpv4Net, resolveKeaLeases)

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

func handleJson(r *http.Request, database *sql.DB, w http.ResponseWriter, resolveIpv6 bool, preferIpv4Net string, resolveKeaLeases bool) {
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
		lookupEntry(&entry, resolveIpv6, preferIpv4Net, resolveKeaLeases)
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(entries); err != nil {
		http.Error(w, "internal server error, failed to encode JSON response", http.StatusInternalServerError)
	}
}

func StartAPI(port int, database *sql.DB, resolveIpv6 bool, preferIpv4Net string, filterZeroIps bool, resolveKeaLeases bool) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterHandlers(mux, database, resolveIpv6, preferIpv4Net, filterZeroIps, resolveKeaLeases)
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("API: http://localhost%s/api/current\n", addr)
	if err := ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
	return mux
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

func lookupHostnameFromLeases(mac string, path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			if err == nil {
				err = closeErr
			} else {
				log.Printf("Failed to close file: %v", closeErr)
			}
		}
	}()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return ""
	}

	mac = strings.ToLower(mac)
	for _, rec := range records {
		if len(rec) < 9 {
			continue
		}
		leaseMac := strings.ToLower(strings.TrimSpace(rec[1]))
		if leaseMac == mac {
			return strings.TrimSpace(rec[8])
		}
	}
	return ""
}

func lookupEntryFunc(entry *db.ArpEntry, resolveIpv6 bool, preferIpv4Net string, resolveKeaLeases bool) {
	names, err := netLookupAddr(firstMatchOrEmpty(entry.IPv4, preferIpv4Net))
	if err == nil && len(names) > 0 && names[0] != "" {
		entry.Hostname = names[0]
		return
	}

	if resolveIpv6 {
		names, err = netLookupAddr(firstMatchOrEmpty(entry.IPv6, ""))
		if err == nil && len(names) > 0 && names[0] != "" {
			entry.Hostname = names[0]
			return
		}
	}

	if resolveKeaLeases && entry.MAC != "" {
		for _, file := range leasesFiles {
			leaseName := lookupHostnameFromLeases(entry.MAC, file)
			if leaseName != "" {
				entry.Hostname = leaseName
				return
			}
		}
	}
}

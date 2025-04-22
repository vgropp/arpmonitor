package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
)

func StartAPI(port int, db *sql.DB) {
	http.HandleFunc("/api/current", func(w http.ResponseWriter, r *http.Request) {
		daysStr := r.URL.Query().Get("days")
		days := 7
		if daysStr != "" {
			if parsed, err := strconv.Atoi(daysStr); err == nil {
				days = parsed
			}
		}

		entries, err := GetRecentEntries(db, days)
		if err != nil {
			http.Error(w, "error on reading entries", http.StatusInternalServerError)
			return
		}

		for _, entry := range entries {
			lookupEntry(&entry)
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

		entries, err := GetRecentEntries(db, days)
		if err != nil {
			http.Error(w, "error on reading entries", http.StatusInternalServerError)
			return
		}

		// Ausgabe im OpenWRT Ethers Format
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("# MAC-Adresse          Hostname             IPv4-Adresse      IPv6-Adresse\n"))

		for _, entry := range entries {

			lookupEntry(&entry)

			fmt.Fprintf(w, "%-20s %-20s %-15s %-15s\n", entry.MAC, entry.Hostname, entry.IPv4, entry.IPv6)
		}
	})

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("API verfügbar unter http://localhost%s/api/current\n", addr)
	http.ListenAndServe(addr, nil)
}

func lookupEntry(entry *ArpEntry) {
	names, err := net.LookupAddr(entry.IPv4)
	if err == nil && len(names) > 0 {
		entry.Hostname = names[0]
	} else {
		names, err = net.LookupAddr(entry.IPv4)
		if err == nil && len(names) > 0 {
			entry.Hostname = names[0]
		}
	}
}

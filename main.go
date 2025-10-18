package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vgropp/arpmonitor/api"
	"github.com/vgropp/arpmonitor/internal/arp"
	"github.com/vgropp/arpmonitor/internal/db"
)

const IPV4_PREFERED = "192.168."

func main() {
	iface := flag.String("iface", "eth0", "interface for ARP/NDP Monitoring")
	dbfile := flag.String("db", "/var/lib/arpmonitor/arpmonitor.db", "path to database file")
	resolveIpv6 := flag.Bool("resolve-ipv6", false, "resolve IPv6 addresses")
	resolveKeaLeases := flag.Bool("resolve-kea-leases", true, "resolve kea leases for hostnames")
	filterZeroIps := flag.Bool("filter-zero-ips", true, "filter out 0.0.0.0 IP addresses (default: true)")
	preferIpv4Net := flag.String("prefer-ipv4-net", IPV4_PREFERED, "network prefix for IPv4-Adressen, which will be prefered if multiple addresses are available (default: 192.168.)")
	port := flag.Int("port", 8567, "HTTP API Port")
	flag.Parse()

	database, err := db.InitDB(*dbfile)
	if err != nil {
		log.Fatalf("DB Fehler: %v", err)
	}
	defer func() {
		closeErr := database.Close()
		if closeErr != nil && err == nil {
			err = fmt.Errorf("database.Close: %w", closeErr)
		}
	}()

	go arp.StartSniffer(*iface, database)
	go api.StartAPI(*port, database, *resolveIpv6, *preferIpv4Net, *filterZeroIps, *resolveKeaLeases)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

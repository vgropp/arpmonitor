package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	iface := flag.String("iface", "eth0", "Netzwerkschnittstelle für ARP/NDP Monitoring")
	dbfile := flag.String("db", "/var/lib/arpmonitor/arpmonitor.db", "path to database file")
	resolveIpv6 := flag.Bool("resolve-ipv6", false, "Netzwerkschnittstelle für ARP/NDP Monitoring")
	port := flag.Int("port", 8567, "HTTP API Port")
	flag.Parse()

	db, err := InitDB(*dbfile)
	if err != nil {
		log.Fatalf("DB Fehler: %v", err)
	}
	defer db.Close()

	go StartSniffer(*iface, db)
	go StartAPI(*port, db, *resolveIpv6)

	// Warten auf Signal zum Beenden
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

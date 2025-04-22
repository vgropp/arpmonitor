package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
)

func main() {
    iface := flag.String("iface", "eth0", "Netzwerkschnittstelle für ARP/NDP Monitoring")
    port := flag.Int("port", 8253, "HTTP API Port")
    flag.Parse()

    db, err := InitDB("arp_events.sqlite")
    if err != nil {
        log.Fatalf("DB Fehler: %v", err)
    }
    defer db.Close()

    go StartSniffer(*iface, db)
    go StartAPI(*port, db)

    // Warten auf Signal zum Beenden
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
    <-sig
    fmt.Println("Beende ARP Monitor...")
}
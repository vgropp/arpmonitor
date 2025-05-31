package arp

import (
	"database/sql"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/vgropp/arpmonitor/internal/db"
)

var insertARPEvent = db.InsertARPEvent

func StartSniffer(iface string, database *sql.DB) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error while opening %s: %v", iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp or icmp6"); err != nil {
		log.Fatalf("BPF-Filter error: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ProcessPacket(packet, database)
	}
}

func ProcessPacket(packet gopacket.Packet, database *sql.DB) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	var eth *layers.Ethernet
	if ethLayer != nil {
		eth = ethLayer.(*layers.Ethernet)
	}

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		ip := net.IP(arp.SourceProtAddress).String()
		mac := net.HardwareAddr(arp.SourceHwAddress).String()
		insertARPEvent(database, ip, mac)
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv6)
		if icmp.TypeCode.Type() == 136 { // Neighbor Advertisement
			if ndpLayer := packet.Layer(layers.LayerTypeIPv6); ndpLayer != nil && eth != nil {
				ip6 := ndpLayer.(*layers.IPv6).SrcIP.String()
				mac := eth.SrcMAC.String()
				insertARPEvent(database, ip6, mac)
			}
		}
	}
}

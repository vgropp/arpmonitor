package arp

import (
	"database/sql"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vgropp/arpmonitor/internal/db"
)

// Mock InsertARPEvent
var inserted []struct{ ip, mac string }

func mockInsertARPEvent(database *sql.DB, ip, mac string) {
	inserted = append(inserted, struct{ ip, mac string }{ip, mac})
}

func TestProcessPacket_ARP(t *testing.T) {
	// Patch db.InsertARPEvent
	origInsert := db.InsertARPEvent
	insertARPEvent = mockInsertARPEvent
	defer func() { insertARPEvent = origInsert }()

	inserted = nil

	// Build ARP packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SourceProtAddress: []byte{192, 168, 1, 10},
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte{192, 168, 1, 1},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, eth, arpLayer)
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	ProcessPacket(packet, nil)

	if len(inserted) != 1 {
		t.Fatalf("expected 1 insert, got %d", len(inserted))
	}
	if inserted[0].ip != "192.168.1.10" || inserted[0].mac != "00:11:22:33:44:55" {
		t.Errorf("got insert %v, want ip=192.168.1.10 mac=00:11:22:33:44:55", inserted[0])
	}
}

func TestProcessPacket_ICMPv6_NA(t *testing.T) {
	origInsert := insertARPEvent
	insertARPEvent = mockInsertARPEvent
	defer func() { insertARPEvent = origInsert }()

	inserted = nil

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       0, // will be set by FixLengths
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     255,
		SrcIP:        []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:        []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}
	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(136, 0), // Neighbor Advertisement
	}
	naPayload := []byte{
		0x60, 0, 0, 0, // flags + reserved
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // target address
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	gopacket.SerializeLayers(buf, opts, eth, ip6, icmp6, gopacket.Payload(naPayload))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	for _, l := range packet.Layers() {
		t.Logf("Layer: %v", l.LayerType())
	}

	ProcessPacket(packet, nil)

	if len(inserted) != 1 {
		t.Fatalf("expected 1 insert, got %d", len(inserted))
	}
	if inserted[0].ip != "fe80::1" || inserted[0].mac != "00:11:22:33:44:55" {
		t.Errorf("got insert %v, want ip=fe80::1 mac=00:11:22:33:44:55", inserted[0])
	}
}

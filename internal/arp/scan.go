package arp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const (
	// scanGap spreads a sweep over a few seconds instead of a single burst.
	scanGap = 20 * time.Millisecond
	// maxScanHosts keeps a misconfigured large network from being flooded.
	maxScanHosts = 4094
	scanSnapLen  = 128
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// packetWriter is the part of a pcap handle the scanner needs.
type packetWriter interface {
	WritePacketData(data []byte) error
}

// StartScanner sends ARP requests for the whole subnet of iface at the given
// interval. It only asks: the answers reach the sniffer like any other ARP
// packet and update last_seen there. An interval <= 0 turns the scanner off.
func StartScanner(iface string, interval time.Duration) {
	if interval <= 0 {
		return
	}
	for {
		if err := scanOnce(iface); err != nil {
			log.Printf("arp scan failed: %v", err)
		}
		time.Sleep(interval)
	}
}

func scanOnce(iface string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return err
	}
	src, targets, err := scanTargets(addrs)
	if err != nil {
		return fmt.Errorf("%s: %w", iface, err)
	}
	// a handle of its own, so sending never interferes with the capture
	handle, err := pcap.OpenLive(iface, scanSnapLen, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()
	return sendRequests(handle, ifi.HardwareAddr, src, targets, scanGap)
}

// scanTargets returns the source address and all hosts of its subnet, without
// the addresses of the interface itself. The first IPv4 address is the source.
func scanTargets(addrs []net.Addr) (net.IP, []net.IP, error) {
	var src net.IP
	var subnet *net.IPNet
	own := map[string]bool{}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		own[ip4.String()] = true
		if src == nil {
			src, subnet = ip4, ipNet
		}
	}
	if src == nil {
		return nil, nil, errors.New("no IPv4 address")
	}
	ones, bits := subnet.Mask.Size()
	hostBits := bits - ones
	if hostBits < 2 {
		return nil, nil, fmt.Errorf("subnet %s has no hosts to scan", subnet)
	}
	if 1<<hostBits-2 > maxScanHosts {
		return nil, nil, fmt.Errorf("subnet %s is too large to scan", subnet)
	}

	first := binary.BigEndian.Uint32(src.Mask(subnet.Mask).To4())
	var targets []net.IP
	for i := uint32(1); i < 1<<hostBits-1; i++ {
		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, first+i)
		if !own[ip.String()] {
			targets = append(targets, ip)
		}
	}
	return src, targets, nil
}

func sendRequests(w packetWriter, mac net.HardwareAddr, src net.IP, targets []net.IP, gap time.Duration) error {
	for _, target := range targets {
		frame, err := arpRequest(mac, src, target)
		if err != nil {
			return err
		}
		if err := w.WritePacketData(frame); err != nil {
			return err
		}
		time.Sleep(gap)
	}
	return nil
}

func arpRequest(mac net.HardwareAddr, src, target net.IP) ([]byte, error) {
	eth := layers.Ethernet{SrcMAC: mac, DstMAC: broadcastMAC, EthernetType: layers.EthernetTypeARP}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   mac,
		SourceProtAddress: src.To4(),
		DstHwAddress:      make(net.HardwareAddr, 6),
		DstProtAddress:    target.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

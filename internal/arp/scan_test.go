package arp

import (
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ipNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	subnet.IP = ip
	return subnet
}

func TestScanTargetsCoverSubnetWithoutOwnAddresses(t *testing.T) {
	addrs := []net.Addr{
		ipNet(t, "fe80::1/64"),
		ipNet(t, "192.168.10.1/24"),
		ipNet(t, "192.168.10.156/24"),
	}
	src, targets, err := scanTargets(addrs)
	if err != nil {
		t.Fatal(err)
	}
	if src.String() != "192.168.10.1" {
		t.Errorf("source %s", src)
	}
	if len(targets) != 252 {
		t.Fatalf("expected 252 targets, got %d", len(targets))
	}
	if first, last := targets[0].String(), targets[len(targets)-1].String(); first != "192.168.10.2" || last != "192.168.10.254" {
		t.Errorf("range %s - %s", first, last)
	}
	for _, target := range targets {
		if target.String() == "192.168.10.156" {
			t.Error("own second address is a target")
		}
	}
}

func TestScanTargetsRejectsUnusableSubnets(t *testing.T) {
	cases := map[string][]net.Addr{
		"no ipv4":   {ipNet(t, "fe80::1/64")},
		"too large": {ipNet(t, "10.0.0.1/8")},
		"point":     {ipNet(t, "10.0.0.1/32")},
		"pair":      {ipNet(t, "10.0.0.1/31")},
	}
	for name, addrs := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := scanTargets(addrs); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScanTargetsAcceptsLargestAllowedSubnet(t *testing.T) {
	_, targets, err := scanTargets([]net.Addr{ipNet(t, "10.0.0.1/20")})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != maxScanHosts-1 {
		t.Fatalf("got %d targets", len(targets))
	}
}

type recorder struct {
	frames [][]byte
	err    error
}

func (r *recorder) WritePacketData(data []byte) error {
	r.frames = append(r.frames, append([]byte(nil), data...))
	return r.err
}

func TestSendRequestsBuildsValidARPRequests(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	src := net.IPv4(192, 168, 10, 1)
	target := net.IPv4(192, 168, 10, 42)
	w := &recorder{}
	if err := sendRequests(w, mac, src, []net.IP{target}, 0); err != nil {
		t.Fatal(err)
	}
	if len(w.frames) != 1 {
		t.Fatalf("got %d frames", len(w.frames))
	}
	packet := gopacket.NewPacket(w.frames[0], layers.LayerTypeEthernet, gopacket.Default)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.DstMAC.String() != "ff:ff:ff:ff:ff:ff" || eth.SrcMAC.String() != mac.String() {
		t.Errorf("ethernet %s -> %s", eth.SrcMAC, eth.DstMAC)
	}
	request := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	if request.Operation != layers.ARPRequest {
		t.Errorf("operation %d", request.Operation)
	}
	if got := net.IP(request.SourceProtAddress).String(); got != "192.168.10.1" {
		t.Errorf("source %s", got)
	}
	if got := net.IP(request.DstProtAddress).String(); got != "192.168.10.42" {
		t.Errorf("target %s", got)
	}
	if got := net.HardwareAddr(request.SourceHwAddress).String(); got != mac.String() {
		t.Errorf("source mac %s", got)
	}
}

func TestSendRequestsStopsOnError(t *testing.T) {
	w := &recorder{err: errors.New("down")}
	targets := []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)}
	if err := sendRequests(w, net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.IPv4(10, 0, 0, 3), targets, 0); err == nil {
		t.Fatal("expected error")
	}
	if len(w.frames) != 1 {
		t.Errorf("sent %d frames after error", len(w.frames))
	}
}

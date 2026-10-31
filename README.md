# arpmonitor

`arpmonitor` is a lightweight Go service that monitors ARP (and optionally NDP) entries on a specified network interface, logs changes into a SQLite database, and exposes a simple HTTP API to query the data in either `ethers`-style output or JSON format.

---

## Features

- Monitors ARP (IPv4) and optionally NDP (IPv6) entries
- Stores one row per MAC/IP pair in a SQLite database, so its size depends on the devices in the network, not on the traffic
- Optionally scans the subnet actively with ARP requests, which also finds devices that stay silent
- Provides a simple HTTP API
- Supports both `ethers` output and structured JSON
- Preferential IPv4 subnet logic for better IP assignment tracking

---

## Installation

```bash
git clone https://github.com/yourusername/arpmonitor.git
cd arpmonitor
go build -o arpmonitor
```

libpcap-dev is needed `sudo apt-get update && sudo apt-get install -y libpcap-dev`

---

## Usage

Run the service (typically with elevated privileges):

```bash
sudo ./arpmonitor [flags]
```

---

## Flags

| Flag                 | Description                                                                 | Default                              |
|----------------------|-----------------------------------------------------------------------------|--------------------------------------|
| `-iface`            | Network interface to monitor                                                | `eth0`                               |
| `-db`               | Path to the SQLite database file                                            | `/var/lib/arpmonitor/arpmonitor.db`  |
| `-resolve-ipv6`     | Enable resolving IPv6 (NDP) addresses                                       | `false`                              |
| `-filter-zero-ips`  | Filter out `0.0.0.0` addresses                                              | `true`                               |
| `-prefer-ipv4-net`  | IPv4 network prefix to prefer if multiple IPs are assigned to a MAC         | `192.168.`                           |
| `-port`             | Port on which the HTTP API server will listen                               | `8567`                               |
| `-arp-scan-interval` | Send ARP requests for the whole subnet of the interface at this interval, e.g. `5m` (`0` disables) | `0`                                  |
| `-retention-days`   | Remove MAC/IP pairs not seen for this many days, keeps the newest pair of each MAC (`0` disables) | `30`                                 |

---

## Active ARP scan

By default the monitor only listens, and on a switch port it mostly sees broadcasts. With `-arp-scan-interval`, it also sends one ARP request per address of the interface's first IPv4 subnet, 20 ms apart, skipping its own addresses. Answers are recorded by the sniffer like any other packet, so `last_seen` then reflects whether a device is online right now.

The scan only asks and changes nothing on other devices. It covers subnets of up to 4094 hosts, other subnets are not scanned. A /24 costs about 250 packets of 42 bytes per run. Sending needs the same `CAP_NET_RAW` as capturing.

---

## Upgrading from the event table

Older versions stored one row per packet in `arp_events`. On the first start, that table is folded into `arp_seen` and the file is compacted. The API is unavailable until this has finished, about a minute for 85 million rows. Back up the file first.

---

## API Endpoints

### `GET /api/ethers?days=N`

Returns MAC → IP mappings seen in the last `N` days in classic `/etc/ethers` format:

```
00:11:22:33:44:55        192.168.1.10 fe80::98b4:bb2a:1122:3344
aa:bb:cc:dd:ee:ff myhost 192.168.1.11
```

---

### `GET /api/current?days=N`

Returns current known MAC → IP mappings as JSON (from the last `N` days):

```json
[
  {
    "mac": "00:11:22:33:44:55",
    "ipv4": [
      "192.168.1.10",
      "0.0.0.0",
      "169.254.87.1"
    ],
    "ipv6": [
      "fe80::98b4:bb2a:1122:3344",
      "2001:d2:11c:2200:a1c4:3544:122:3344"
    ],
    "first_seen": "2025-05-02T08:01:12Z",
    "last_seen": "2025-05-30T14:12:00Z"
  },
  {
    "mac": "aa:bb:cc:dd:ee:ff",
    "ipv4": [
        "192.168.1.11"
    ],
    "first_seen": "2025-05-20T19:44:02Z",
    "last_seen": "2025-05-30T14:15:10Z"
  }
]
```

---

## Example

Run the monitor on interface `br0`, store DB at `/opt/arpmonitor.db`, serve API on port `8567`, and prefer `10.0.` IPv4 addresses:

```bash
sudo ./arpmonitor \
  --iface=br0 \
  --db=/opt/arpmonitor.db \
  --port=8567 \
  --resolve-ipv6=true \
  --prefer-ipv4-net=10.0.
```

Then access the API:

```bash
curl http://localhost:8567/api/ethers?days=7
curl http://localhost:8567/api/current?days=3
```

## License

This project is licensed under the [MIT License](./LICENSE).

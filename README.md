# arpmonitor

`arpmonitor` is a lightweight Go service that monitors ARP (and optionally NDP) entries on a specified network interface, logs changes into a SQLite database, and exposes a simple HTTP API to query the data in either `ethers`-style output or JSON format.

---

## Features

- Monitors ARP (IPv4) and optionally NDP (IPv6) entries
- Writes changes to a persistent SQLite database
- Provides a simple HTTP API
- Supports both `ethers` output and structured JSON
- Filters `0.0.0.0` addresses by default
- Preferential IPv4 subnet logic for better IP assignment tracking

---

## Installation

```bash
git clone https://github.com/yourusername/arpmonitor.git
cd arpmonitor
go build -o arpmonitor
```

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
| `--iface`            | Network interface to monitor                                                | `eth0`                               |
| `--db`               | Path to the SQLite database file                                            | `/var/lib/arpmonitor/arpmonitor.db`  |
| `--resolve-ipv6`     | Enable resolving IPv6 (NDP) addresses                                       | `false`                              |
| `--filter-zero-ips`  | Filter out `0.0.0.0` addresses                                              | `true`                               |
| `--prefer-ipv4-net`  | IPv4 network prefix to prefer if multiple IPs are assigned to a MAC         | `192.168.`                           |
| `--port`             | Port on which the HTTP API server will listen                               | `8567`                               |

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
    "last_seen": "2025-05-30T14:12:00Z"
  },
  {
    "mac": "aa:bb:cc:dd:ee:ff",
    "ipv4": [
        "192.168.1.11"
    ],
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
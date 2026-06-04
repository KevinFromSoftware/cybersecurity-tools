# 🔍 Port Scanner

A simple TCP port scanner written in Python — built as a cybersecurity learning project.

## What it does

Connects to each port in a given range on a target host using TCP sockets.
If the connection succeeds → the port is **open**.
If it fails or times out → the port is **closed or filtered**.

## Usage

```bash
# Scan default range (ports 1–1024)
python scanner.py scanme.nmap.org

# Scan a specific range
python scanner.py scanme.nmap.org -s 1 -e 500

# Scan with a longer timeout (useful for slow hosts)
python scanner.py 192.168.1.1 -s 20 -e 100 -t 1.0
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `host` | Target IP or hostname | required |
| `-s` / `--start` | Start port | 1 |
| `-e` / `--end` | End port | 1024 |
| `-t` / `--timeout` | Timeout in seconds | 0.5 |

## Example output

```
====================================================
  Target  : 45.33.32.156
  Ports   : 1 - 1024
  Started : 2025-06-03 14:22:01
====================================================

  [OPEN]  Port    22  →  SSH
  [OPEN]  Port    80  →  HTTP
  [ -- ]  Scanned up to port 100...

====================================================
  Scan complete! 2 open port(s) found.
  Open ports: 22, 80
  Finished : 2025-06-03 14:22:18
====================================================
```

## How it works (the code)

The core of the scanner is just one function:

```python
def scan_port(host, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))  # returns 0 if open
        return result == 0
```

`socket.connect_ex()` tries to complete a TCP handshake.
- Returns `0` → connection succeeded → **port is open**
- Returns anything else → connection refused/timed out → **port is closed**

## ⚠️ Legal & ethical notice

**Only scan hosts you have explicit permission to scan.**

Unauthorized port scanning may be illegal in your country and violates the terms of service of most networks.

Safe targets for learning:
- `scanme.nmap.org` — officially provided by the Nmap project for practice
- Your own machine: `127.0.0.1` or `localhost`
- Your own home network (e.g. `192.168.1.1`)

## Concepts covered

- TCP/IP and the three-way handshake
- Python `socket` module
- Command-line interfaces with `argparse`
- Hostname resolution (DNS)
- Port numbers and common services

## Ideas for extending this project

- [ ] Add UDP scanning support
- [ ] Add banner grabbing (read the service's greeting message)
- [ ] Export results to a `.txt` or `.csv` file
- [ ] Add threading to scan faster
- [ ] Build a simple GUI with `tkinter`

## Requirements

Python 3.7+ — no external libraries needed.

---

*Part of my cybersecurity learning journey at Noroff University College.*
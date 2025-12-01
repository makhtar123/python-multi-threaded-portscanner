# Python Multi-Threaded Port Scanner

Multi-threaded network reconnaissance tool built with Python. It performs both standard TCP Connect scans and stealth SYN (Half-Open) scans using raw packet manipulation via Scapy.

## Features

*   **Hybrid Scanning:** Supports both full TCP Connect (3-way handshake) and Stealth SYN scans.
*   **Multi-Threading:** Utilizes the Producer-Consumer pattern (Queue) to scan ports concurrently for high performance.
*   **Service Enumeration:** Performs active banner grabbing to identify running services.
*   **Host Discovery:** Implements a smart "Combo Check" (ICMP + TCP 80 + TCP 443) to detect live hosts behind firewalls.
*   **Smart Fallbacks:** Automatically detects root privileges and switches scan modes accordingly.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/makhtar123/port-scanner.git
    cd port-scanner
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

**Note:** SYN scans and Host Discovery require `sudo` (Root) privileges.

### 1. Standard Connect Scan (Safe Mode)
```bash
python netscan.py -t 192.168.1.1 -sT
```

### 2. Stealth SYN Scan + Banner Grabbing
```bash
sudo python netscan.py -t 192.168.1.1 -sV
```

### 3. Scan Specific Port Range
```bash
sudo python netscan.py -t 192.168.1.1 -sp 1 -ep 80
```

### 4. Scan a list of Ports
```bash
sudo python netscan.py -t 192.168.1.1 -p 1 2 3 4
```
### Arguments

| Flag | Long Flag | Description | Required |
| :--- | :--- | :--- | :---: |
| `-t` | `--target` | The target IP address to scan. | **Yes** |
| `-p` | `--ports` | Specific list of ports to scan (e.g. `-p 21 80 443`). | No |
| `-sp` | `--startport` | Starting port for a range scan. | No |
| `-ep` | `--endport` | Ending port for a range scan. | No |
| `-sT` | `--connect` | Perform a full TCP Connect Scan (Non-Sudo). | No |
| `-sV` | `--serviceversion` | Enable active banner grabbing. | No |
| `-Pn` | `--noping` | Skip host discovery (useful for firewalls). | No |
| `-T` | `--threads` | Set number of threads (Default: 100). | No |

## Disclaimer
This tool is developed for educational purposes and authorized security testing only. The developer is not responsible for any misuse or damage caused by this tool. Always obtain permission before scanning a network you do not own.
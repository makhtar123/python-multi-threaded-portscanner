import socket
import threading
import queue
import argparse
import sys
import os
import codecs
import errno  
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, Raw, DNS, DNSQR
from top_1000_ports import common_ports

def load_udp_payloads(filepath='nmap-payloads'):
    """
    Parses the local nmap-payloads file and returns a dictionary
    mapping integer ports to raw byte payloads.
    """
    payloads = {}
    
    # Look for the file in the exact same folder as this script
    if not os.path.exists(filepath):
        print(f"[!] Warning: '{filepath}' not found in the current directory. UDP scans will use empty packets.")
        return payloads

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(maxsplit=2)
            if len(parts) == 3 and parts[0].lower() == 'udp':
                port_string = parts[1]
                raw_payload_str = parts[2].strip('"')
                
                try:
                    # Safely convert "\x00" text into Python bytes
                    # Use 'unicode_escape' which is the modern Python 3 way to do this
                    payload_bytes = codecs.decode(raw_payload_str, 'unicode_escape').encode('latin1')
                except Exception:
                    continue 

                for port in port_string.split(','):
                    if port.isdigit():
                        payloads[int(port)] = payload_bytes

    print(f"[*] Successfully loaded {len(payloads)} UDP payloads from {filepath}.")
    return payloads

class PortScanner:
    def __init__(self, target, scan_type, threads, banner_opt, no_ping):
        self.target = target
        self.scan_type = scan_type # 0 = Connect, 1 = SYN, 2 = UDP
        self.threads = threads
        self.banner_opt = banner_opt
        self.no_ping = no_ping
        
        self.show_all = False #  Show closed/filtered states for explicit port lists
        
        if self.scan_type == 2:
            self.udp_payloads = load_udp_payloads()
        else:
            self.udp_payloads = {}

        # Encapsulated State
        self.q = queue.Queue()
        self.lock = threading.Lock()

    def check_host_up(self):
        try:
            # Crafting an ICMP echo request
            icmp_packet = IP(dst=self.target) / ICMP()
            resp = sr1(icmp_packet, timeout=2,verbose=0)
            if resp is not None:
                return True
            
            #Sending a TCP SYN Ping on Port 80
            packet = IP(dst=self.target) / TCP(dport=80, flags='S')
            resp = sr1(packet, timeout=2, verbose=0)
            if resp is not None and resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12: #0x12 flag is a hexidecimal representation of the SYN-ACK flag
                    rst_packet = IP(dst=self.target) / TCP(dport=80, flags='R')
                    send(rst_packet, verbose=0)
                    return True
                else:
                    return True

            #Sending a TCP SYN ping on port 443
            packet = IP(dst=self.target) / TCP(dport=443, flags='S')
            resp = sr1(packet, timeout=2, verbose=0)
            if resp is not None and resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12:
                    rst_packet = IP(dst=self.target) / TCP(dport=443, flags='R')
                    send(rst_packet, verbose=0)
                    return True
                else:
                    return True
            return False
            
        except PermissionError:
            print("Error: Host discovery requires sudo/root privileges")
            sys.exit(1)
        except socket.error as e:
            print(f"Network error: {e}") 
            return False  

    def _connect_scan(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((self.target, port)) # returns 0 to indicate TCP 3-way handshake succeeded 
            
            if result == 0:
                # --- OPEN PORT LOGIC ---
                if self.banner_opt:
                    if port == 80:
                        provoke_msg = "HEAD / HTTP/1.1\r\nHost: " + str(self.target) + "\r\n\r\n"
                        sock.send(provoke_msg.encode())
                    try:
                        # converting raw network bytes into readable text
                        byte_information = sock.recv(1024)
                        banner_information = byte_information.decode('utf-8', errors='ignore').strip()
                        with self.lock:
                            print(f"Port {port}: OPEN - {banner_information}")
                    except socket.timeout:
                        with self.lock:
                            print(f"Port {port}: OPEN - COULDN'T RETRIEVE BANNER")
                    except socket.error:
                        with self.lock:
                            print(f"Port {port}: OPEN - COULDN'T RETRIEVE BANNER")
                else:
                    try:
                        default_service = socket.getservbyport(port, 'tcp')
                        with self.lock:
                            print(f"Port {port}: OPEN - {default_service}")
                    except socket.error:
                        with self.lock:
                            print(f"Port {port}: OPEN - UNKNOWN")
            

            elif self.show_all:
                try:
                    service_name = socket.getservbyport(port, 'tcp')
                except OSError:
                    service_name = "UNKNOWN"

                if result == errno.ECONNREFUSED:
                    with self.lock:
                        print(f"Port {port}: CLOSED - {service_name}")
                else:
                    # If it's not 0 (Open) and not Refused (Closed), it timed out (Filtered)
                    with self.lock:
                        print(f"Port {port}: FILTERED - {service_name}")

        except socket.error:
            pass
        finally:
            sock.close()


    def _syn_scan(self, port):
        try:
            try:
                service_name = socket.getservbyport(port, 'tcp')
            except OSError:
                service_name = "UNKNOWN"
            # crafting syn packet
            packet = IP(dst=self.target) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=1, verbose=0)
            
            # Check for Filtered (Timeout / None)
            if response is None:
                if self.show_all:
                    with self.lock:
                        print(f"Port {port}: FILTERED - {service_name}")
            
            elif response.haslayer(TCP):
                flags = response[TCP].flags
                
                # Check for Open (SYN-ACK)
                if flags == 0x12:
                    if self.banner_opt:
                        """
                        Scapy operates at too low of a level to easily read web server banners. Temporarily
                        need to switch to standard Python socket function to complete a full connection and 
                        grab banner
                        """
                        
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        try:
                            sock.connect((self.target, port))                         
                            if port == 80:
                                provoke_msg = "HEAD / HTTP/1.1\r\nHost: " + str(self.target) + "\r\n\r\n"
                                sock.send(provoke_msg.encode())                     
                            byte_information = sock.recv(1024)
                            if not byte_information:
                                with self.lock:
                                    print(f"Port {port}: OPEN - COULDN'T RETRIEVE BANNER")
                            else:
                                banner_information = byte_information.decode('utf-8', errors='ignore').strip()
                                with self.lock:
                                    print(f"Port {port}: OPEN - {banner_information}")
                        except (socket.timeout, socket.error):
                            with self.lock:
                                print(f"Port {port}: OPEN - COULDN'T RETRIEVE BANNER")
                        finally:
                            sock.close()
                    else:
                        try:
                            default_service = socket.getservbyport(port, 'tcp')
                            with self.lock:
                                print(f"Port {port}: OPEN - {default_service}")
                        except OSError:
                            with self.lock:
                                print(f"Port {port}: OPEN - UNKNOWN")
                    # Send RST Packet after getting a SYN-ACK response
                    rst_packet = IP(dst=self.target) / TCP(dport=port, flags='R')
                    send(rst_packet, verbose=0)
                
                # Check for Closed (RST or RST-ACK)
                elif (flags == 0x14 or flags == 0x04) and self.show_all:
                    with self.lock:
                        print(f"Port {port}: CLOSED - {service_name}")

        except socket.error:
            pass
    
    def _udp_scan(self, port):
        try:
            # 1. Build the base IP and UDP layers
            base_packet = IP(dst=self.target) / UDP(dport=port)
            
            # 2. Attach the application payload (if we parsed one for this port)
            if port == 53:
                # rd=1 means "Recursion Desired", qname is the site we are asking about
                packet = base_packet / DNS(rd=1, qd=DNSQR(qname="google.com"))
            elif port in self.udp_payloads:
                packet = base_packet / Raw(load=self.udp_payloads[port])
            else:
                packet = base_packet # Send empty packet if no payload exists
                
            # 3. Send the packet. 
            response = sr1(packet, timeout=2, verbose=0)
            
            # --- 4. ANALYZE THE RESPONSE ---
            
            # SCENARIO A: Timeout (No Response)
            if response is None:
                if self.show_all:
                    with self.lock:
                        print(f"Port {port} (UDP): OPEN|FILTERED")
            
            # SCENARIO B: Got a UDP packet back
            elif response.haslayer(UDP):
                # Look up the human-readable service name (e.g., 'domain' for 53)
                try:
                    service = socket.getservbyport(port, 'udp')
                except OSError:
                    service = "UNKNOWN"
                    
                with self.lock:
                    print(f"Port {port} (UDP): OPEN - {service}")
            
            # SCENARIO C: We got an ICMP Error back
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                
                # ICMP Type 3 means "Destination Unreachable"
                if int(icmp_layer.type) == 3:
                    
                    # Code 3 means "Port Unreachable" -> CLOSED
                    if int(icmp_layer.code) == 3:
                        if self.show_all:
                            with self.lock:
                                print(f"Port {port} (UDP): CLOSED")
                                
                    # Code 1, 2, 9, 10, or 13 means a Firewall explicitly blocked it
                    elif int(icmp_layer.code) in [1, 2, 9, 10, 13]:
                        if self.show_all:
                            with self.lock:
                                print(f"Port {port} (UDP): FILTERED (ICMP Code {icmp_layer.code})")

        except Exception:
            # Silently catch any Scapy or socket crash on this specific thread
            pass

    def worker(self):
        # This is the generic thread loop
        while True:
            try:
                port = self.q.get()
                if self.scan_type == 1:
                    self._syn_scan(port)
                elif self.scan_type == 2:
                    self._udp_scan(port) 
                else:
                    self._connect_scan(port)
            except Exception:
                pass
            finally:
                self.q.task_done()

    def load_ports(self, start, end, port_list):
        """
        Function acts a producer, filling the queue 
        with port numbers for the threads to scan
        """
        if start is not None and end is not None and port_list:
            print("Either pick a range of ports or a list of ports")
            sys.exit(1)
        
        # CASE 1: Specific List (Enable show_all)
        elif port_list:
            self.show_all = True 
            port_string = ' '.join(port_list)
            final_list = port_string.replace(',', ' ').split()
            for port in final_list:
                if not port:
                    continue
                try:
                    port_num = int(port)
                    if 1 <= port_num <= 65535:
                        self.q.put(port_num)
                    else:
                        print(f"Port out of range ignored: {port_num}")
                except ValueError:
                    print(f"Invalid Port ignored: {port}")
        
        # CASE 2: Range (Disable show_all)
        elif start is not None and end is not None:
            self.show_all = False 
            if start > end:
                print("Start port can't be greater than end port")
                sys.exit(1)
            for i in range(start, end + 1):
                self.q.put(i)
        
        # CASE 3: Default (Disable show_all)
        else:
            self.show_all = False
            print("Scanning 1000 most common ports")
            for i in common_ports:
                self.q.put(i)

    def run(self):
        # 1. Check Sudo (if SYN or UDP)
        if self.scan_type in (1, 2) and os.geteuid() != 0:
            print("Need Sudo.")
            sys.exit(1)

        # 2. Host Discovery
        if not self.no_ping:
            if not self.check_host_up():
                print("Host Down.")
                sys.exit(1)

        # 3. Start Threads
        print(f"Scanning {self.target}...")
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
        
        # 4. Wait
        self.q.join()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Python Port Scanner")
    parser.add_argument("-t", "--target", help="Target IP Address", required=True)
    parser.add_argument("-sp", "--startport", type=int, help="Start Port")
    parser.add_argument("-ep", "--endport", type = int, help="End Port")
    parser.add_argument("-p", "--ports", type=str, help="Enter a list of ports", nargs="+")
    parser.add_argument("-sT", "--connect", action="store_true", help="Enable connect scan")
    parser.add_argument("-sU", "--udpscan", action="store_true", help="Enable UDP Scan")
    parser.add_argument("-sV", "--serviceversion",action="store_true", help="Enable Service Version Detection")
    parser.add_argument("-Pn", "--noping", action="store_true", help="Skip Host Discovery")
    parser.add_argument("-T", "--threads", type=int, help="Set the amount of threads. Default is 100 for Connect, 25 for SYN, and 15 for UDP")
    return parser.parse_args()

def main():
    args = parse_arguments()
    """ 
    Use fewer threads for SYN/UDP scans because Scapy's sr1() is not ideal for
    heavy concurrent use. Too many threads can cause missed or mismatched packet
    responses, leading to inaccurate scan results.
    """
    if args.connect:
        default_threads = 100
    elif args.udpscan:
        default_threads = 15
    else:
        default_threads = 25
    if args.connect:
        # User explicitly chose Connect Scan
        scan_type = 0
    elif os.geteuid() == 0:
        # Check if user is root and proceed to the chosen scan type
        if args.udpscan:
            scan_type = 2
        else:
            scan_type = 1
    else:
        # User is NOT Root, and didn't specify a type.
        print("No sudo/root privileges detected. Defaulting to TCP Connect scan.")
        scan_type = 0

    scanner = PortScanner(
        target=args.target,
        scan_type=scan_type,
        threads=args.threads or default_threads,
        banner_opt=args.serviceversion,
        no_ping=args.noping
    )
    scanner.load_ports(args.startport, args.endport, args.ports)

    scanner.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(1)

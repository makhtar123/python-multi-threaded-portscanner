import socket
import threading
import queue
import argparse
import sys
import os
from scapy.all import IP, TCP, ICMP, sr1, send
from top_1000_ports import common_ports


class PortScanner:
    def __init__(self, target, scan_type, threads, banner_opt, no_ping):
        self.target = target
        self.scan_type = scan_type # 0 = Connect, 1 = SYN
        self.threads = threads
        self.banner_opt = banner_opt
        self.no_ping = no_ping
        
        # Encapsulated State
        self.q = queue.Queue()
        self.lock = threading.Lock()

    def check_host_up(self):
        try:
            icmp_packet = IP(dst=self.target) / ICMP()
            resp = sr1(icmp_packet, timeout=2,verbose=0)
            if resp is not None:
                return True
            packet = IP(dst=self.target) / TCP(dport=80, flags='S')
            resp = sr1(packet, timeout=1, verbose=0)
            if resp is not None and resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12:
                    rst_packet = IP(dst=self.target) / TCP(dport=80, flags='R')
                    send(rst_packet, verbose=0)
                    return True
                else:
                    return True
        
            packet = IP(dst=self.target) / TCP(dport=443, flags='S')
            resp = sr1(packet, timeout=1, verbose=0)
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
            result = sock.connect_ex((self.target, port)) 
            
            if result == 0:
                if self.banner_opt == 1:
                    if port == 80:
                        provoke_msg = "HEAD / HTTP/1.1\r\nHost: " + str(self.target) + "\r\n\r\n"
                        sock.send(provoke_msg.encode())
                    try:
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
                            print(f"Port {port}: OPEN - UNKOWN")       
        except socket.error:
            pass
        finally:
            sock.close()


    def _syn_scan(self, port):
        try:
            packet = IP(dst=self.target) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=1, verbose=0)
            if response is not None and response.haslayer(TCP):
                flags = response[TCP].flags
                if flags == 0x12:
                    if self.banner_opt == 1:
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
                        except:
                            with self.lock:
                                print(f"Port {port}: OPEN - UNKNOWN")

                    rst_packet = IP(dst=self.target) / TCP(dport=port, flags='R')
                    send(rst_packet, verbose=0)

        except socket.error:
            pass

    def worker(self):
        # This is the generic thread loop
        while True:
            try:
                port = self.q.get()
                if self.scan_type == 1:
                    self._syn_scan(port)
                else:
                    self._connect_scan(port)
            except Exception:
                pass
            finally:
                self.q.task_done()

    def load_ports(self, start, end, port_list):
        if start and end and port_list:
            print("Either pick a range of ports or a list of ports")
            sys.exit(1)
        elif port_list:
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
        elif start and end:
            if start > end:
                print("Start port can't be greater than end port")
                sys.exit(1)
            for i in range(start, end + 1):
                self.q.put(i)
        else:
            print("Scanning 1000 most common ports")
            for i in common_ports:
                self.q.put(i)

    def run(self):
        # 1. Check Sudo (if SYN)
        if self.scan_type == 1 and os.geteuid() != 0:
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
    parser.add_argument("-sV", "--serviceversion",action="store_true", help="Enable Service Version Detection")
    parser.add_argument("-Pn", "--noping", action="store_true", help="Skip Host Discovery")
    parser.add_argument("-T", "--threads", type=int, help="Set the amount of threads. Default is 100")
    return parser.parse_args()

def main():
    args = parse_arguments()
    if args.connect:
        # User explicitly chose Connect Scan
        scan_type = 0
    elif os.geteuid() == 0:
        # User is Root, so we default to the better SYN Scan
        scan_type = 1
    else:
        # User is NOT Root, and didn't specify a type.
        print("No sudo/root privileges detected. Defaulting to TCP Connect scan.")
        scan_type = 0

    scanner = PortScanner(
        target=args.target,
        scan_type=scan_type,
        threads=args.threads or 100,
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
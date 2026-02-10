import socket
import threading
from queue import Queue
import ipaddress
import sys
import argparse
import time

# thread safety locks
print_lock = threading.Lock()
counter_lock = threading.Lock()

processed_tasks = 0

def get_banner(s):
    """Attempts to retrieve a service banner."""
    try:
        s.settimeout(2.0)
        banner = s.recv(1024)
        
        # If no banner, poke for HTTP/others
        if not banner:
            s.send(b'HEAD / HTTP/1.1\r\n\r\n')
            banner = s.recv(1024)
            
        decoded_banner = banner.decode(errors='ignore').strip()
        return " ".join(decoded_banner.split())[:100]
    except:
        return None

def scan_port(ip, port, timeout, verbose, total_tasks, grab_banner):
    """
    Performs port scan on single port/ip combo
    
    :param ip: Target IP Address
    :param port: Target TCP port
    :param timeout: Time in seconds before connection drops
    :param verbose: Whether to print progress updates to console periodically
    :param total_tasks: The total amount of port/ip combos in queue
    :param grab_banner: Whether the scan should attempt to Banner Grab
    """
    global processed_tasks
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        conn = s.connect_ex((str(ip), port))
        if conn == 0:
            banner_text = ""
            if grab_banner:
                found_banner = get_banner(s)
                if found_banner:
                    banner_text = f" | Banner: {found_banner}"
            
            with print_lock:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                sys.stdout.flush()
                print(f"[+] {ip}:{port} is OPEN{banner_text}")
        s.close()
    except:
        pass

    if verbose:
        with counter_lock:
            processed_tasks += 1
            # update TUI every 5 tasks or on last task to reduce overhead
            if processed_tasks % 5 == 0 or processed_tasks == total_tasks:
                percent = (processed_tasks / total_tasks) * 100
                # ljust(70) pads line with spaces
                status = f"[*] Progress: {percent:.2f}% ({processed_tasks}/{total_tasks} tasks)".ljust(70)
                sys.stdout.write(f"\r{status}")
                sys.stdout.flush()

def worker(q, total_tasks, timeout, verbose, grab_banner):
    """Worker thread function."""
    while True:
        try:
            item = q.get_nowait()
        except:
            # sleep to reduce CPU overhead if producer is slow
            time.sleep(0.01)
            continue
            
        if item is None:
            q.task_done()
            break
        
        ip, port = item
        scan_port(ip, port, timeout, verbose, total_tasks, grab_banner)
        q.task_done()

def producer(q, network, start_port, end_port, thread_count):
    """Producer thread function."""
    max_buffer = thread_count * 5 # buffer set to 5x threads to keep workers fed
    for ip in network:
        for port in range(start_port, end_port + 1):
            while q.qsize() >= max_buffer:
                time.sleep(0.05)
            q.put((ip, port))

def main():
    parser = argparse.ArgumentParser(description="Multi-Threaded Port Scanner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", required=True)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--banner", action="store_true")

    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.target, strict=False)
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        else:
            start_port = end_port = int(args.ports)
    except Exception as e:
        print(f"Error parsing input: {e}")
        return

    total_tasks = network.num_addresses * (end_port - start_port + 1)
    q = Queue()

    print(f"[*] Target: {args.target} | Ports: {args.ports} | Threads: {args.threads}")

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, total_tasks, args.timeout, args.verbose, args.banner))
        t.start()
        threads.append(t)

    try:
        producer(q, network, start_port, end_port, args.threads)
    except KeyboardInterrupt:
        print("\n[!] User Interrupted. Cleaning up...")

    # signal threads to stop
    for _ in range(args.threads):
        q.put(None)

    for t in threads:
        t.join()

    print("\n[*] Scan complete.")

if __name__ == "__main__":
    main()
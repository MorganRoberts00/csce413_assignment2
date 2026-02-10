import socket
import subprocess
import time
import logging
import threading

# config
SEQUENCE = [1234, 5678, 9012]
PROTECTED_PORT = 2222
WINDOW = 10

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def start_dummy_service():
    """Listens on 2222 so the connection isn't refused."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', PROTECTED_PORT))
        s.listen(5)
        logging.info(f"[*] Service Thread: Listening on {PROTECTED_PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                logging.info(f"[!] SUCCESS: Connection accepted from {addr}")
                conn.sendall(b"You have passed the trial. Welcome.\n")

def manage_iptables(ip, action="insert"):
    flag = "-I" if action == "insert" else "-D"
    cmd = ["iptables", flag, "INPUT", "1", "-p", "tcp", "-s", ip, "--dport", str(PROTECTED_PORT), "-j", "ACCEPT"]
    subprocess.run(cmd)

def listen_for_knocks():
    progress = {}
    socks = []
    for port in SEQUENCE:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', port))
        s.setblocking(False)
        socks.append(s)

    logging.info(f"[*] Knock Server: Monitoring ports {SEQUENCE}")

    while True:
        for i, s in enumerate(socks):
            try:
                _, addr = s.recvfrom(1024)
                ip, port_rec = addr[0], SEQUENCE[i]
                now = time.time()

                if ip not in progress or (now - progress[ip]['time']) > WINDOW:
                    progress[ip] = {'index': 0, 'time': now}

                if port_rec == SEQUENCE[progress[ip]['index']]:
                    progress[ip]['index'] += 1
                    if progress[ip]['index'] == len(SEQUENCE):
                        manage_iptables(ip, "insert")
                        del progress[ip]
                else:
                    if ip in progress: del progress[ip]
            except BlockingIOError:
                continue
        time.sleep(0.1)

if __name__ == "__main__":
    # wipe iptables and set drop by default on protected port
    subprocess.run(["iptables", "-F", "INPUT"])
    subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(PROTECTED_PORT), "-j", "DROP"])

    # start service thread 
    service_thread = threading.Thread(target=start_dummy_service, daemon=True)
    service_thread.start()

    # listen for knocks
    listen_for_knocks()

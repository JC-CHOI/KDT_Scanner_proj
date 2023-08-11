import threading
import scantype
from scapy.all import *

def get_src_port(use_rand_src):
    if use_rand_src:
        return RandShort()
    else:
        return 12345
    
def perform_port_scan(target_host, num_threads, target_ports, scan_type, use_rand_src):
    port_segments = [target_ports[i::num_threads] for i in range(num_threads)]
    threads = []
    results = []

    for i in range(num_threads):
        if scan_type == "syn":
            thread = threading.Thread(target=scantype.syn_scanner, args=(target_host, port_segments[i], get_src_port(use_rand_src), results))
        elif scan_type == "tcp":
            thread = threading.Thread(target=scantype.tcp_connect_scan, args=(target_host, port_segments[i], get_src_port(use_rand_src), results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return results
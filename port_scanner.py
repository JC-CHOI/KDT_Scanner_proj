# -*- coding: utf-8 -*-
# UTF-8 encoding when using korean

import threading
import scantype
from scapy.all import *
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_src_port(use_rand_src):
    if use_rand_src:
        return RandShort()
    else:
        return 12345
    
def perform_port_scan(target_host, num_threads, target_ports, scan_type, use_rand_src):
    port_segments = [target_ports[i::num_threads] for i in range(num_threads)]
    threads = []
    results = []
    
    print(f"Starting {scan_type} scan...\n")
    
    for i in range(num_threads):
        if scan_type == "syn":
            thread = threading.Thread(target=scantype.syn_scanner, args=(target_host, port_segments[i], get_src_port(use_rand_src), results))
        elif scan_type == "tcp":
            thread = threading.Thread(target=scantype.tcp_connect_scan, args=(target_host, port_segments[i], results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
        
    results_with_services = []
    for port in results:
        try:
            service_name = socket.getservbyport(port)
            results_with_services.append((port, service_name))
        except (OSError, socket.error, socket.herror, socket.gaierror, socket.timeout):
            results_with_services.append((port, "Unknown"))
    
    results_with_services.sort()
    return results_with_services
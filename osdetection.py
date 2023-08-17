from scapy.all import *

def get_ttl(target_host):
    pkt = IP(dst=target_host) / ICMP()
    response = sr1(pkt, timeout=1, verbose=0)
    if response:
        return response.ttl
    else:
        return None

def fingerprint_os(ttl):
    if 0 <= ttl <= 64:
        return "Linux/Unix"
    elif 65 <= ttl <= 128:
        return "Windows"
    elif 129 <= ttl <= 255:
        return "Cisco"
    else:
        return "Unknown"

def os_detect(target_host):

    ttl = get_ttl(target_host)
    if ttl is not None:
        print(f"TTL 값 : {target_host}: {ttl}")
        os_guess = fingerprint_os(ttl)
        print(f"예상되는 OS: {os_guess}")
    else:
        print(f"탐지에 실패 :  {target_host}")
        
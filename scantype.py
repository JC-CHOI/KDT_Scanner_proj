# -*- coding: utf-8 -*-
# UTF-8 encoding when using korean

from scapy.all import *

# TCP conncet scan function
def tcp_connect_scan(target_host, target_ports, results):
    for port in target_ports:

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target_host, port))
                if result == 0:
                    results.append(port)
        except Exception as e:
            pass

def syn_scanner(target_host, target_ports, src_port, results):
    for port in target_ports:
        packet = IP(dst=target_host)/TCP(sport=src_port, dport=port, flags='S')
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            flags = response.getlayer(TCP).flags  # 응답 패킷의 플래그값 확인
            if flags == 0x12:  # SYN-ACK 플래그 값
                results.append(port)
            elif flags == 0x14:  # RST 플래그 값
                pass#results.append((port, "CLOSED (RST)"))
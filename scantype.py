from scapy.all import *

# TCP conncet scan function
def tcp_connect_scan(target_host, target_ports, src_port, results):
    for port in target_ports:

        # SYN 패킷 생성 및 전송
        syn_packet = IP(dst=target_host) / TCP(sport=src_port, dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        # 응답 받았고, TCP 계층이 있을 경우 처리
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN/ACK 패킷 확인
                results.append(port)
                # SYN/ACK를 받았을 때, 해당 포트는 열려있다고 판단
                # 연결을 완료하는 ACK 패킷 전송
                ack_packet = IP(dst=target_host) / TCP(sport=src_port, dport=port, flags="A")
                send(ack_packet, verbose=0)

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
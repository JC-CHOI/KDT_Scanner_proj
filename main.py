from scapy.all import *
from datetime import datetime
import argparse


# TCP connect 스캔 함수
def tcp_connect_scan(target_host, target_ports):
    open_ports = []
    for port in target_ports:
        src_port = RandShort()  # 랜덤 소스 포트 생성

        # SYN 패킷 생성 및 전송
        syn_packet = IP(dst=target_host) / TCP(sport=src_port, dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        # 응답 받았고, TCP 계층이 있을 경우 처리
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN/ACK 패킷 확인
                open_ports.append(port)
                # SYN/ACK를 받았을 때, 해당 포트는 열려있다고 판단
                # 연결을 완료하는 ACK 패킷 전송
                ack_packet = IP(dst=target_host) / TCP(sport=src_port, dport=port, flags="A")
                send(ack_packet, verbose=0)

    return open_ports

def main():
    # 명령어 인수 파싱을 위한 argparse 설정
    parser = argparse.ArgumentParser(description="Simple port scanner using Scapy")
    parser.add_argument("host", help="Target host IP address")
    parser.add_argument("ports", help="Port range to scan (e.g., 1-100)")
    args = parser.parse_args()

    # 입력된 명령어 인수 사용
    target_host = args.host
    start_time = datetime.now()

    # 입력 받은 포트 범위 파싱하여 리스트로 변환
    start_port, end_port = map(int, args.ports.split("-"))
    target_ports = range(start_port, end_port + 1)

    # TCP connect 스캔 수행
    open_ports = tcp_connect_scan(target_host, target_ports)

    end_time = datetime.now()
    elapsed_time = end_time - start_time
    print("Scan completed in:", elapsed_time)

    # 열린 포트 출력
    if open_ports:
        print("Open ports:", open_ports)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()

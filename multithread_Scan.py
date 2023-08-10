import sys
import threading
from queue import Queue
from scapy.all import *
from datetime import datetime

def syn_scanner(target_ip, port_queue, results):
    while not port_queue.empty():
        port = port_queue.get()
        packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            flags = response.getlayer(TCP).flags  # 응답 패킷의 플래그값 확인
            if flags == 0x12:  # SYN-ACK 플래그 값
                results.append((port, "OPEN (SYN-ACK)"))
            elif flags == 0x14:  # RST 플래그 값
                pass#results.append((port, "CLOSED (RST)"))

def main():
    if len(sys.argv) != 4:
        print("Usage: python syn_scanner_multithread.py <target_ip> <port_start> <port_end>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_range_start = int(sys.argv[2])
    port_range_end = int(sys.argv[3])
    port_range = range(port_range_start, port_range_end+1)
    #port_range = range(1,65537)
    start_time = datetime.now()

    # 스캔할 포트들을 큐에 넣어줍니다.
    port_queue = Queue()
    for port in port_range:
        port_queue.put(port)

    # 결과를 저장할 리스트
    results = []

    # 멀티스레딩으로 스캔을 실행합니다.
    threads = []
    for _ in range(100):  # 원하는 스레드 수 (예: 10개)
        thread = threading.Thread(target=syn_scanner, args=(target_ip, port_queue, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = datetime.now()
    elapsed_time = end_time - start_time
    print("Scan completed in:", elapsed_time)

    # 결과 출력
    if results:
        for port, status in results:
            print(f"Port {port} is {status}")
    else:
        print(f"No open ports found on {target_ip}")

if __name__ == "__main__":
    main()

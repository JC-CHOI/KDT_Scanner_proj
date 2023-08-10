from datetime import datetime
from scapy.all import *
import argparse
import multithread_Scan
import threading
import tcp_full_scan

#--rand-src 파트
def get_src_port(use_rand_src):
    if use_rand_src:
        return RandShort()
    else:
        return 12345
        
def main():
    # 명령어 인수 파싱을 위한 argparse 설정
    parser = argparse.ArgumentParser(description="Simple port scanner using Scapy")
    parser.add_argument("host", help="Target host IP address")
    parser.add_argument("ports", help="Port range to scan (e.g., 1-100)")
    parser.add_argument("-sS", action="store_true", help="Use SYN scan mode")
    parser.add_argument("-sT", action="store_true", help="Use full scan mode")
    parser.add_argument("--rand-src", action="store_true", help="Use random source port")
    args = parser.parse_args()

    # 입력된 명령어 인수 사용
    target_host = args.host
    start_time = datetime.now()

    # 입력 받은 포트 범위 파싱하여 리스트로 변환
    start_port, end_port = map(int, args.ports.split("-"))
    target_ports = range(start_port, end_port + 1)
    
    # 스캔 수행
    num_threads = 50  # 원하는 스레드 수
    port_segments = [target_ports[i::num_threads] for i in range(num_threads)]
    
    threads = []
    results = []
   
   #멀티 스레딩 
    for i in range(num_threads):
        if args.sS:
            thread = threading.Thread(target=multithread_Scan.syn_scanner, args=(target_host, port_segments[i], get_src_port(args.rand_src), results))
        elif args.sT:
            thread = threading.Thread(target=tcp_full_scan.tcp_connect_scan, args=(target_host, port_segments[i], get_src_port(args.rand_src), results))
        else: #별도 지정 안했을 때 full scan
            thread = threading.Thread(target=tcp_full_scan.tcp_connect_scan, args=(target_host, port_segments[i], get_src_port(args.rand_src), results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = datetime.now()
    elapsed_time = end_time - start_time
    print("Scan completed in:", elapsed_time)

    # 열린 포트 출력
    if results:
        print("Open ports:", results)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()

from datetime import datetime
from scapy.all import *
import argparse
import icmp_ping_scan
from PortParse import portParsing
from port_scanner import perform_port_scan, get_src_port
        
def main():
    # 명령어 인수 파싱을 위한 argparse 설정
    parser = argparse.ArgumentParser(description="Simple port scanner using Scapy")
    parser.add_argument("host", help="Target host IP address")
    parser.add_argument("-p", help="Port range to scan (e.g., 1-100 or 22,44,80)", type=portParsing)
    parser.add_argument("-sS", action="store_true", help="Use SYN scan mode")
    parser.add_argument("-sT", action="store_true", help="Use full scan mode")
    parser.add_argument("-sn", action="store_true", help="Perform ICMP Ping scan using icmp_ping_scan.py")
    parser.add_argument("--rand-src", action="store_true", help="Use random source port")
    args = parser.parse_args()

    # 입력된 명령어 인수 사용
    target_host = args.host
    start_time = datetime.now()
    
    if args.sn:
        icmp_ping_scan.icmp_ping_scan(target_host)
    else:    
        # 스캔 수행
        num_threads = 100  # 원하는 스레드 수
        if args.p is None:  # -p 옵션이 지정되지 않았을 때
            target_ports = range(1, 1025)  # 기본적으로 1~1024 포트 범위 설정
        else:
            target_ports = args.p
            
        if args.sS:
            scan_type = "syn"
        elif args.sT:
            scan_type = "tcp"
        else: #별도 지정 안했을 때 full scan
            scan_type = "tcp"
                
        results = perform_port_scan(target_host, num_threads, target_ports, scan_type, args.rand_src)
        
        # 열린 포트 출력
        if results:
            print("Open ports:", results)
        else:
            print("No open ports found.")
            
    end_time = datetime.now()
    elapsed_time = end_time - start_time
    print("Scan completed in:", elapsed_time)

if __name__ == "__main__":
    main()

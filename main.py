from datetime import datetime
from scapy.all import *
import argparse
import icmp_ping_scan
from PortParse import portParsing, use_top_ports
from port_scanner import perform_port_scan
from find_service import service_detect
from osdetection import os_detect

def main():
    # 명령어 인수 파싱을 위한 argparse 설정
    parser = argparse.ArgumentParser(description="Simple port scanner using Scapy")
    parser.add_argument("host", help="Target host IP address")
    parser.add_argument("-p", help="Port range to scan (e.g., 1-100 or 22,44,80)", type=portParsing)
    parser.add_argument('--top-ports', type=int, help='Number of top ports to use')
    parser.add_argument("-sS", action="store_true", help="Use SYN scan mode")
    parser.add_argument("-sT", action="store_true", help="Use full scan mode")
    parser.add_argument("-sn", action="store_true", help="Perform ICMP Ping scan")
    parser.add_argument("-sV", action="store_true", help="Service detection mode")
    parser.add_argument("-O", action="store_true", help="OS detection mode")
    parser.add_argument("--rand-src", action="store_true", help="Use random source port")
    args = parser.parse_args()

    # 입력된 명령어 인수 사용
    target_host = args.host
    start_time = datetime.now()
    
    if args.O:
        os_detect(target_host)

    if args.sn:
        icmp_ping_scan.icmp_ping_scan(target_host)
    else:    
        # 스캔 수행
        num_threads = 50  # 원하는 스레드 수
        if args.p is not None:  # -p 옵션 지정
            target_ports = args.p
        elif args.top_ports is not None:
            target_ports = use_top_ports(args.top_ports)
        else:
            target_ports = range(1, 1025)  # 기본적으로 1~1024 포트 범위 설정
                
        if args.sS:
            scan_type = "syn"
        elif args.sT:
            scan_type = "tcp"
        else: #별도 지정 안했을 때 full scan
            scan_type = "tcp"
                
        results = perform_port_scan(target_host, num_threads, target_ports, scan_type, args.rand_src)
        
        # 열린 포트 출력
        if results:
            open_port = []
            print("port    service")
            for result in results:
                open_port.append(result[0])
                print("{:<{width}}{}".format(result[0], result[1], width=8))
        else:
            print("No open ports found.")
        print(" ")
        
        if args.sV:
            service_detect(target_host, open_port)
            
    end_time = datetime.now()
    elapsed_time = end_time - start_time
    print("\nScan completed in:", elapsed_time)

if __name__ == "__main__":
    main()

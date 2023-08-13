from scapy.all import *
import socket
import ipaddress
import logging
import platform
import concurrent.futures

# Unix 계열일 경우에만 L3RawSocket 설정 적용
if platform.system() != "Windows":
    try:
        from scapy.layers.inet import IP, ICMP
        conf.L3socket = L3RawSocket
    except ImportError:
        pass # print("L3RawSocket 사용 불가")

# '-'로 ip 범위 지정한 경우
def parse_targets(targets):
    target_ips = []

    # '-'와 '.'이 있는 경우 IP 범위로 간주
    if '-' in targets and '.' in targets:
        parts = targets.split('.')
        x = parts[-1].split('-')
        # 올바른 범위 형식인지 확인
        if len(x) == 2 and x[0].isdigit() and x[1].isdigit():
            start, end = map(int, x)
            base_ip = ".".join(parts[:-1])
            # 범위 내의 각 IP 주소를 추가
            for i in range(start, end + 1):
                target_ips.append(f"{base_ip}.{i}")
        else:
            # 범위가 아닌 경우 그대로 추가
            target_ips.append(targets)
    else:
        # '-'가 없는 경우 그대로 추가
        target_ips.append(targets)
        
    return target_ips

# CIDR 형식 입력값인 경우
def handle_cidr(target):
    target_ip = ipaddress.ip_network(target, strict=False)
    # IPv4와 CIDR 형식인 경우 호스트 리스트(IP 리스트) 반환
    if isinstance(target_ip, ipaddress.IPv4Network) and '/' in target:
        return list(target_ip.hosts())
    return []


# 단일 IP 형식인 경우
def handle_single_ip(target):
    return [str(ipaddress.ip_address(target))]

# 호스트 형식(URL)인 경우 
def handle_host_name(target):
    try:
        # 호스트 이름을 IP로 변환
        target_ip = socket.gethostbyname(target)
        return [target_ip]
    except socket.gaierror:
        # 변환 실패시 오류 메시지 출력 (ipv4, CIDR, URL 아닌 경우)
        print(f"Invalid target: {target}")
        return []

# IP 리스트에 ICMP Echo Request 전송
def send_icmp_request(target_ips):
    up_hosts = []
    # 각 IP에 대해 ICMP Echo Request 전송
    # timeout 시간 줄여둔 상태라 정확도 떨어지면 시간 늘려야 함
    response = sr1(IP(dst=str(target_ips)) / ICMP(), timeout=0.5, verbose=0)
    if response and response.haslayer(ICMP):
        # 응답이 있으면 up_hosts에 추가
        up_hosts.append(target_ips)
        print(f"Host is up: {target_ips}")
    return up_hosts

# ICMP Ping Scan
def icmp_ping_scan(targets):
    up_hosts = []

    # Windows에서 경고 메시지 출력을 숨기기 위한 로깅 설정
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    try:
        target_ips = []
        # '-'로 범위 지정한 경우 (ex. 192.168.0.1-20)
        if '-' in targets and '.' in targets:
            target_ips = parse_targets(targets)
        # '/'로 CIDR 표기한 경우 (ex. 192.168.0.0/24)
        elif '/' in targets:
            target_ips = handle_cidr(targets)
        # 단일 IP인 경우 (ex. 192.168.0.1)
        else:
            target_ips = handle_single_ip(parse_targets)
        # IPv4, CIDR이 아닌 경우(ex. google.com)
    except ValueError:
        target_ips = handle_host_name(targets)
        
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(send_icmp_request, target) for target in target_ips]

        for future in concurrent.futures.as_completed(futures):
            up_hosts += future.result()

    if not up_hosts:
        print("No hosts up.")

    return up_hosts
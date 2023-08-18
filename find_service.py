# -*- coding: utf-8 -*-
# UTF-8 encoding when using korean

import socket
import re


REQ = [
	b'',
    b'USER YuiL\r\n',
    b'HELO YuiL\r\n',
    b'GET / HTTP/1.0\r\n\r\n',
    b'\r\n\r\n',
    b'\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03',
    b'\x00\x00\x00\xa4\xffSMBr\x00\x00\x00\x08\x01@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x06\x00\x00\x01\x00\x00\x81\x00\x02PC\x00NETWORK PROGRA\x02\x00MICROSOFT NETWORKS 1.0\x02\x00MICROSOFT NETWORKS 3.0\x02\x00LANMAN1.0\x02\x00LM12X000\x02\x00Samba\x00\x02\x00NT LANMAN 1.0\x02\x00NT LM 0.12\x00Samba\x00\x00NT LANMAN 1.0\x00NT LM 0.12',
    b'\0\0\0\x71\x6a\x81\x6e\x30\x81\x6b\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a\xa4\x81\x5e\x30\x5c\xa0\x07\x03\x05\0\x50\x80\0\x10\xa2\x04\x1b\x02NM\xa3\x17\x30\x15\xa0\x03\x02\x01\0\xa1\x0e\x30\x0c\x1b\x06krbtgt\x1b\x02NM\xa5\x11\x18\x0f19700101000000Z\xa7\x06\x02\x04\x1f\x1e\xb9\xd9\xa8\x17\x30\x15\x02\x01\x12\x02\x01\x11\x02\x01\x10\x02\x01\x17\x02\x01\x01\x02\x01\x03\x02\x01\x02',
    b'\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
    b'\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00\x00\x01\x00\x00\x81\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x31\x2e\x30\x33\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x33\x2e\x30\x00\x02\x4c\x41\x4e\x00\x4d\x41\x4e\x31\x2e\x30\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x00\x32\x00\x02\x53\x61\x6d\x62\x61\x00\x02\x4e\x54\x20\x4c\x41\x4e\x00\x4d\x41\x4e\x20\x31\x2e\x30\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x00\x2e\x31\x32\x00',
    b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x02\x04\0\x80\0',
    b'\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00',
    b'\x00\x9c\x00\x01\x1a\x2b\x3c\x4d\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff\x00\x01\x6e\x6f\x6e\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x79\x75\x69\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x00\x9c\x00\x01\x1a+<M\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff\x00\x01none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00nmap\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x30\x16\x02\x01\x05\x77\x11\x30\x0f\xa0\x0d\x30\x0b\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02\x01',
    b'\x60\x28\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x03\0\0*%\xe0\0\0\0\0\0Cookie: mstshash=yuil\r\n\x01\0\x08\0\x03\0\0\0'
]

# DNS 서비스
REQ_UDP = [
	b'\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
]

TIMEOUT = 2

# Service patterns 파일 읽기
with open('service_patterns', 'r') as file:
    lines = file.readlines()

# "서비스 이름"을 키로, 정규표현식을 값으로 하는 딕셔너리 초기화
service_patterns = {}
for line in lines:
    parts = line.strip().split(',')
    service_name = parts[0]
    regex = parts[2] if len(parts) > 2 else ''
    if service_name not in service_patterns:
        service_patterns[service_name] = []
    service_patterns[service_name].append(regex.encode())
    
def get_matching_service(host, port, req_list, protocol="TCP"):
    try:
        if protocol == "TCP":
            for req in req_list:
                # with가 자동으로 s.close() 수행
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(TIMEOUT)
                    s.connect((host, port))
                    
                    try:
                        s.sendall(req)
                        banner = s.recv(1024)
                        # print(f'{port} :', banner)

                        for service_name, patterns in service_patterns.items():
                            for regex in patterns:
                                # compiled_regex = re.compile(regex, re.IGNORECASE)
                                compiled_regex = re.compile(regex)
                                if compiled_regex.search(banner):
                                    return service_name
                    except (socket.timeout, socket.error):
                        # 타임아웃이나 오류 발생하면 그냥 다음 요청으로 넘어감
                        pass

        elif protocol == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT)
                s.sendto(req_list[0], (host, port))
                banner, _ = s.recvfrom(1024)

                for service_name, patterns in service_patterns.items():
                    for regex in patterns:
                        compiled_regex = re.compile(regex, re.IGNORECASE)
                        if compiled_regex.search(banner):
                            return service_name

    except Exception as e:
        pass

    return None

def service_detect(host, open_ports):
    # open_ports에서 각 포트에 대해 get_matching_service 함수를 호출
    print("Starting detailed service detection...\n")
    for port in open_ports:
        matched_service = get_matching_service(host, port, REQ, "TCP")
        
        if not matched_service:
            matched_service = get_matching_service(host, port, REQ_UDP, "UDP")

        if matched_service:
            print(f"Matched service on port {port}: {matched_service}")
        else:
            print(f"Matched service on port {port}: {socket.getservbyport(port)}?")
            
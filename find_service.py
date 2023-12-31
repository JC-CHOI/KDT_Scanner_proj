# -*- coding: utf-8 -*-
# UTF-8 encoding when using korean

import socket
import re
import ssl
import concurrent.futures

# TCP 전송하는 요청 메시지
REQ = [
	b'',
    b'USER YuiL\r\n',
    b'HELO YuiL\r\n',
    b'GET / HTTP/1.0\r\n\r\n',
    b'HELP\r\n',
    b'\r\n\r\n',
    b'\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
    b'\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03',
    b'\x00\x00\x00\xa4\xffSMBr\x00\x00\x00\x08\x01@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x06\x00\x00\x01\x00\x00\x81\x00\x02PC\x00NETWORK PROGRA\x02\x00MICROSOFT NETWORKS 1.0\x02\x00MICROSOFT NETWORKS 3.0\x02\x00LANMAN1.0\x02\x00LM12X000\x02\x00Samba\x00\x02\x00NT LANMAN 1.0\x02\x00NT LM 0.12\x00Samba\x00\x00NT LANMAN 1.0\x00NT LM 0.12',
    b'\x00\x00\x00\xa4\xffSMBr\x00\x00\x00\x08\x01@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00`@\x00\x01\x00\x00\x81\x00 P2NETWORK PROGRAM 1.0\x00\x02MICROSOF\x00\x03MICROSOF\x00\x02LANMAN1.0\x00\x02LM12X000\x02Sam\x00\x02NT LAN MAN 1.0\x02NTLM 0.12\x00Sam\x00\x02NT LAN MAN 1.0\x02NTLM 0.12\x00',
    b'\0\0\0\x71\x6a\x81\x6e\x30\x81\x6b\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a\xa4\x81\x5e\x30\x5c\xa0\x07\x03\x05\0\x50\x80\0\x10\xa2\x04\x1b\x02NM\xa3\x17\x30\x15\xa0\x03\x02\x01\0\xa1\x0e\x30\x0c\x1b\x06krbtgt\x1b\x02NM\xa5\x11\x18\x0f19700101000000Z\xa7\x06\x02\x04\x1f\x1e\xb9\xd9\xa8\x17\x30\x15\x02\x01\x12\x02\x01\x11\x02\x01\x10\x02\x01\x17\x02\x01\x01\x02\x01\x03\x02\x01\x02',
    b'\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
    b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x02\x04\0\x80\0',
    b'\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00',
    b'\x00\x9c\x00\x01\x1a+<M\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff\x00\x01none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00nmap\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
    b'\x30\x16\x02\x01\x05\x77\x11\x30\x0f\xa0\x0d\x30\x0b\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02\x01',
    b'\x60\x28\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'\x03\0\0*%\xe0\0\0\0\0\0Cookie: mstshash=yuil\r\n\x01\0\x08\0\x03\0\0\0',
    b'OPTIONS / RTSP/1.0\r\n\r\n',
    b'stats\r\n'
]

# UDP 전송하는 요청 메시지
REQ_UDP = [
	b'\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
    b'HELP\r\n',
    b'\x80\xf0\0\x10\0\x01\0\0\0\0\0\0\x20\x43\x4bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0\x21\0\x01',
    b'NQ'
]

# SSL/TLS 전송
REQ_SSL = [
    b"GET / HTTP/1.0\r\n\r\n"
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
    # ','로 나뉜 부분이 3개이면 regex에 정규표현식 저장
    regex = parts[2] if len(parts) > 2 else ''
    if service_name not in service_patterns:
        service_patterns[service_name] = []
    # 바이트 문자열 응답과 비교하기 위해 regex를 바이트 형식으로 인코딩
    service_patterns[service_name].append(regex.encode())

# TCP, SSL, UDP 요청을 보내고, 받은 응답과 일치하는 정규표현식 탐색
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

                        # echo 식별
                        if banner == req and req == b'HELP\r\n':
                            return "echo" 

                        # 응답과 일치하는 정규표현식의 서비스 이름을 반환
                        for service_name, patterns in service_patterns.items():
                            for regex in patterns:
                                compiled_regex = re.compile(regex)
                                if compiled_regex.search(banner):
                                    return service_name
                    # 타임아웃이나 오류 발생하면 그냥 다음 요청으로 넘어감            
                    except (socket.timeout, socket.error):
                        pass

        elif protocol == "SSL":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((host, port))
                
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                secure_socket = ssl_context.wrap_socket(s, server_hostname=host)

                # SSL/TLS 보안 소켓은 한 번의 핸드쉐이크 후 여러 메시지 전송이 가능
                for req in req_list:
                    try:
                        secure_socket.send(req)
                        banner = secure_socket.recv(1024)

                        for service_name, patterns in service_patterns.items():
                            for regex in patterns:
                                compiled_regex = re.compile(regex)
                                if compiled_regex.search(banner):
                                    return service_name
                    # 타임아웃이나 오류 발생하면 그냥 다음 요청으로 넘어감            
                    except (socket.timeout, socket.error, ssl.SSLError):
                        pass

        elif protocol == "UDP":
            for req in req_list:
                # with가 자동으로 s.close() 수행
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(TIMEOUT)
                    # UDP는 연결을 맺지 않으므로 sendto() 사용
                    s.sendto(req, (host, port))
                    
                    # 수신 위주로 오류 예외처리
                    try:
                        banner, _ = s.recvfrom(1024)
                        for service_name, patterns in service_patterns.items():
                            for regex in patterns:
                                compiled_regex = re.compile(regex)
                                if compiled_regex.search(banner):
                                    return service_name
                    # 타임아웃이나 오류 발생하면 그냥 다음 요청으로 넘어감            
                    except (socket.timeout, socket.error):
                        pass

    except Exception as e:
        pass

    return None

def detect_service_for_port(host, port):
    ssl_flag = False
    matched_service = get_matching_service(host, port, REQ, "TCP")        

    if not matched_service:
        matched_service = get_matching_service(host, port, REQ_UDP, "UDP")

    if not matched_service:
        matched_service = get_matching_service(host, port, REQ_SSL, "SSL")
        if matched_service:
            ssl_flag = True

    if matched_service and ssl_flag == True:
        return f"Matched service on port {port}: ssl/{matched_service}"
    elif matched_service and ssl_flag == False:
        return f"Matched service on port {port}: {matched_service}"
    else:
        try:
            service_name = socket.getservbyport(port)
        except OSError:
            service_name = "Unknown"
        return f"Matched service on port {port}: {service_name}?"

def service_detect(host, open_ports):
    print("Starting detailed service detection...\n")
    # open_ports에 값이 있는 경우에만 서비스 탐지 실행
    if open_ports:   
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # detect_service_for_port 함수를 병렬로 실행하고, 결과를 출력
            # concurrent.futures.ThreadPoolExecutor().map() 함수 - 병렬로 작업을 처리해도 결과가 원래의 순서대로 반환됨
            results = list(executor.map(detect_service_for_port, [host]*len(open_ports), open_ports))

        for result in results:
            print(result)
    else:
        print("No open ports found. Service detection was not performed.")
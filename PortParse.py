# -*- coding: utf-8 -*-
# UTF-8 encoding when using korean

def portParsing(portFormat):
    ports = []
    if "-" in portFormat:  ## ex. -p 50-80
        start_port, end_port = map(int, portFormat.split("-"))
        ports = range(start_port, end_port + 1)
    elif "," in portFormat:  ## ex. 55,56,57
        ports = [int(x) for x in portFormat.split(",")]
    elif portFormat.isdigit():  ## ex. -p 55
        return [int(portFormat)]
    return ports

def use_top_ports(num):
    ports = []
    cnt = 0
    
    with open("top-ports.txt", 'r') as file:
        for port in file:
            ports.append(int(port))
            cnt += 1
            if cnt == num:
                break
    return ports

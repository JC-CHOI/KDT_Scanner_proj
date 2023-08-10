
def portParsing(portFormat):
    ports = []
    if "-" in portFormat : ## ex. -p 50-80
        start_port, end_port = map(int, portFormat.split("-"))
        ports = range(start_port, end_port)
    elif "," in portFormat : ## ex. 55,56,57
        #ports = [int(x) for x in portFormat]
        return portFormat
    elif portFormat.isdigit() : ## ex. -p 55
        return int(portFormat)
    elif not portFormat.isdigt() : ## ex. -p ssh
        pass
    else:
        ports = range(1,1024) ## default port setting : 1~1024
    
    return ports


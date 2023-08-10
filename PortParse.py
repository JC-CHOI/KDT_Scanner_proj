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

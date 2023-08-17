import subprocess
import re

def get_ttl(target_host):
    try:
        result = subprocess.run(["ping", "-n", "1", target_host], capture_output=True, text=True, timeout=5)
        output = result.stdout

        ttl_match = re.search(r"TTL=(\d+)", output) # TTL 값을 정규 표현식을 사용하여 추출
        if ttl_match:
            ttl = int(ttl_match.group(1))
            return ttl
        else:
            return None
    except subprocess.TimeoutExpired:
        print("Ping timeout.")
        return None

def fingerprint_os(ttl):
    if 0 <= ttl <= 64:
        return "Linux/Unix"
    elif 65 <= ttl <= 128:
        return "Windows"
    elif 129 <= ttl <= 255:
        return "Cisco"
    else:
        return "Unknown"

def os_detect(target_host):
    ttl = get_ttl(target_host)

    if ttl is not None:
        os_guess = fingerprint_os(ttl)
        print(f"Target : {target_host}")
        print(f"TTL : {ttl}")
        print(f"OS Guess based on TTL : {os_guess}\n")
    else:
        print("TTL not found.")

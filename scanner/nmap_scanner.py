import subprocess
import re


def scan_host(target):
    command = [
        "nmap",
        "-sV",
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    output = result.stdout

    ports = []

    for line in output.splitlines():
        match = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)

        if match:
            ports.append({
                "port": match.group(1),
                "service": match.group(2)
            })

    return {
        "ip_address": target,
        "open_ports": ports
    }


if __name__ == "__main__":
    result = scan_host("192.168.127.1")
    print(result)
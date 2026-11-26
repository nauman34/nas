"""Safe wrapper around the Nmap executable for authorized network assessments."""
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

MAX_NETWORK_ADDRESSES = 256
TIMEOUT_SECONDS = 900


def validate_target(target):
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > MAX_NETWORK_ADDRESSES:
                raise ValueError(f"Network is too large. Limit is {MAX_NETWORK_ADDRESSES} addresses.")
        else:
            ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4/IPv6 address or CIDR network (up to 256 addresses).") from exc
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap was not found. Install Nmap and ensure it is available in PATH.")
    return True


def _run_nmap(args):
    command = ["nmap", "-oX", "-"] + args
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("The scan exceeded the 15-minute time limit.") from exc
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.strip() or "Nmap scan failed.")
    try:
        return ET.fromstring(completed.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Could not parse Nmap output.") from exc


def _parse(root, include_ports=False):
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addresses = host.findall("address")
        ip = next((a.get("addr") for a in addresses if a.get("addrtype") in ("ipv4", "ipv6")), "Unknown")
        mac = next((a.get("addr") for a in addresses if a.get("addrtype") == "mac"), "")
        names = host.find("hostnames")
        hostname = ""
        if names is not None and names.find("hostname") is not None:
            hostname = names.find("hostname").get("name", "")
        item = {"ip": ip, "hostname": hostname, "mac": mac, "ports": []}
        if include_ports:
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    service = port.find("service")
                    item["ports"].append({
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service": service.get("name", "") if service is not None else "",
                        "version": " ".join(filter(None, [
                            service.get("product", "") if service is not None else "",
                            service.get("version", "") if service is not None else ""
                        ])) if service is not None else ""
                    })
        hosts.append(item)
    return hosts


def scan_network(target):
    validate_target(target)
    root = _run_nmap(["-sn", target])
    return {"scan_type": "Host discovery", "target": target, "hosts": _parse(root),
            "note": "Host discovery only; no port scan was performed."}


def scan_target(target):
    validate_target(target)
    if "/" in target and ipaddress.ip_network(target, strict=False).num_addresses != 1:
        raise ValueError("Detailed port/service scanning accepts one IP address only.")
    root = _run_nmap(["-sV", "--top-ports", "1000", "--", target])
    return {"scan_type": "Top 1,000 TCP ports with service detection", "target": target,
            "hosts": _parse(root, include_ports=True),
            "note": "Only open TCP ports are listed. Run only against systems you own or are authorized to assess."}

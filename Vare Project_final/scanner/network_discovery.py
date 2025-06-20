from scapy.all import ARP, Ether, srp
import nmap
import socket

def identify_device(mac):
    OUI_DEVICE_MAP = {
        "00:1C:B3": "Apple Device",
        "3C:5A:B4": "Samsung Device",
        "44:65:0D": "Amazon Echo",
        "78:4F:43": "Google Home",
        "F4:5C:89": "Xiaomi Device",
        "D8:A2:5E": "iPhone",
        "B8:27:EB": "Raspberry Pi",
        # Add more MAC prefixes as needed
    }
    prefix = mac.upper()[0:8]
    return OUI_DEVICE_MAP.get(prefix, "Unknown IoT Device")

def discover_devices(subnet):
    devices = []

    # Primary: ARP Scan
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    seen_ips = set()

    for _, received in result:
        ip = received.psrc
        mac = received.hwsrc
        seen_ips.add(ip)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = identify_device(mac)
        devices.append({'ip': ip, 'mac': mac, 'device_name': hostname})

    # Fallback: Nmap ping scan for anything ARP missed
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=subnet, arguments='-sn')
        for host in nm.all_hosts():
            if host not in seen_ips:
                mac = nm[host]['addresses'].get('mac', '00:00:00:00:00:00')
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except:
                    hostname = identify_device(mac)
                devices.append({'ip': host, 'mac': mac, 'device_name': hostname})
    except Exception as e:
        print(f"Fallback Nmap scan failed: {e}")

    return devices

def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '1-1024', arguments='-sV')
        open_ports = []
        for port in nm[ip]['tcp']:
            if nm[ip]['tcp'][port]['state'] == 'open':
                service = nm[ip]['tcp'][port].get('product', '')
                version = nm[ip]['tcp'][port].get('version', '')
                name = nm[ip]['tcp'][port].get('name', '')
                open_ports.append({
                    'port': port,
                    'product': service,
                    'version': version,
                    'name': name
                })
        return open_ports
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        return []

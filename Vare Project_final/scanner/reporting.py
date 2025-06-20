import json

def generate_report(devices_info, output_file="scan_report.json"):
    report = {"network_scan_results": []}

    for device in devices_info:
        device_report = {
            "device_ip": device.get("device_ip", "Unknown"),
            "device_mac": device.get("device_mac", "Unknown"),
            "device_name": device.get("name", "Unknown"),
            "open_ports": device.get("ports", []),
            "vulnerabilities": device.get("vulnerabilities", []),
            "weak_credentials": device.get("weak_credentials", False),
            "credentials_used": device.get("credentials_used", None),
            "mitigation_recommendations": device.get("mitigations", [])
        }
        report["network_scan_results"].append(device_report)

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Report saved to {output_file}")

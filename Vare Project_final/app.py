from flask import Flask, render_template, send_file, redirect, url_for, request
from scanner.network_discovery import discover_devices, scan_ports
from scanner.cve_lookup import lookup_cves
from scanner.weak_credentials import check_ssh_weak_credentials
from scanner.reporting import generate_report
import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
latest_report_data = []

def generate_mitigation_recommendations(open_ports, weak_credentials_found, cves):
    recommendations = []
    if weak_credentials_found:
        recommendations.append("Change default or weak credentials immediately.")
    if cves:
        recommendations.append("Apply firmware or software updates to patch vulnerabilities.")
    for port_info in open_ports:
        port = port_info.get("port")
        if port in [23, 21]:
            recommendations.append(f"Disable or secure port {port} (insecure protocol).")
    return recommendations

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    subnet = request.args.get('subnet')
    if not subnet:
        return "Subnet not specified", 400

    discovered = discover_devices(subnet=subnet)
    devices = []
    report_data = []

    for dev in discovered:
        ip = dev.get('ip', 'Unknown IP')
        mac = dev.get('mac', 'Unknown MAC')

        try:
            raw_ports = scan_ports(ip)
        except Exception as e:
            print(f"Skipping port scan for {ip}: {e}")
            raw_ports = []

        open_ports = []
        cve_list = []
        weak_credentials_found = False
        creds_used = None

        for port_info in raw_ports:
            query_parts = []

            if port_info.get('product'):
                query_parts.append(port_info['product'])
            if port_info.get('version'):
                query_parts.append(port_info['version'])
            if not query_parts and port_info.get('name'):
                query_parts.append(port_info['name'])

            query = ' '.join(query_parts).strip()

            try:
                cves = lookup_cves(query)
            except Exception as e:
                print(f"Error looking up CVEs for {query}: {e}")
                cves = []

            cve_list.extend(cves)

            open_ports.append({
                'port': port_info['port'],
                'service': query or 'Unknown',
                'cves': cves
            })

            if port_info['port'] == 22:
                weak, creds = check_ssh_weak_credentials(ip)
                weak_credentials_found = weak
                creds_used = creds

        mitigations = generate_mitigation_recommendations(open_ports, weak_credentials_found, cve_list)

        devices.append({
            'ip': ip,
            'mac': mac,
            'open_ports': open_ports,
            'device_name': dev.get('device_name', 'Unknown IoT Device'),
            'weak_credentials': weak_credentials_found,
            'credentials_used': creds_used,
            'mitigations': mitigations
        })

        report_data.append({
            'device_ip': ip,
            'device_mac': mac,
            'device_name': dev.get('device_name', 'Unknown IoT Device'),
            'open_ports': open_ports,
            'vulnerabilities': cve_list,
            'weak_credentials': weak_credentials_found,
            'credentials_used': creds_used,
            'mitigation_recommendations': mitigations
        })

    print(devices)
    global latest_report_data
    latest_report_data = report_data
    generate_report(report_data)


    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template('results.html', devices=devices, timestamp=timestamp)


@app.route('/generate_pdf')
def generate_pdf():
    global latest_report_data

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    
    c.drawString(100, 750, "IoT Network Scan Report")
    c.drawString(100, 730, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y_position = 700
    for item in latest_report_data:
        c.drawString(100, y_position, f"Device: {item['device_name']} IP: {item['device_ip']}")
        y_position -= 20
        if y_position < 100:
            c.showPage()
            y_position = 750

    c.save()
    buffer.seek(0)
    
    return send_file(buffer, as_attachment=True, download_name="IoT_Report.pdf", mimetype='application/pdf')


@app.route('/back')
def back():
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

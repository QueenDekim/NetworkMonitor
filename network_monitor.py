import nmap
import mysql.connector
import json
import time

def scan_network(network, ports):
    
    nm = nmap.PortScanner()
    
    try:
        print(f"Starting scan on network {network} with ports {ports}...")
        nm.scan(hosts=f'{network}', arguments=f'-sV -p {ports} -T4', timeout=120)
        print("Scan completed.")
    except Exception as e:
        print(f"Error during scanning: {e}")
        return

    conn = mysql.connector.connect(
        host='localhost',
        user='username',
        password='password',
        database='network_monitoring'
    )
    cursor = conn.cursor()

    for host in nm.all_hosts():
        print(f"Found device: {host}")

        status = nm[host].state()
        device_info = {
            'hostname': nm[host].hostname(),
            'ports': []
        }

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_info = {
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    'product': nm[host][proto][port].get('product', ''),
                    'version': nm[host][proto][port].get('version', '')
                }
                device_info['ports'].append(port_info)

        device_info_json = json.dumps(device_info)

        cursor.execute("SELECT device_info FROM scans WHERE ip = %s", (host,))
        result = cursor.fetchone()

        if result:
            if result[0] != device_info_json:
                cursor.execute(
                    "UPDATE scans SET status = %s, device_info = %s, timestamp = CURRENT_TIMESTAMP WHERE ip = %s",
                    (status, device_info_json, host)
                )
        else:
            cursor.execute(
                "INSERT INTO scans (ip, status, device_info) VALUES (%s, %s, %s)",
                (host, status, device_info_json)
            )

    conn.commit()
    cursor.close()
    conn.close()

if __name__ == "__main__":
    network = input("Enter the network to scan (e.g., 192.168.1.0/24): ")
    ports = input("Enter the ports to scan (e.g., 22,80,443): ")

    while True:
        scan_network(network, ports)
        print("Waiting for 2 minutes before next scan...")
        time.sleep(120)

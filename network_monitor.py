import nmap
import pymysql
import json
import time
from colorama import Fore
from config import DB_CONFIG

def scan_network(network, ports):
    try:
        nm = nmap.PortScanner()
    except Exception as e:
        print(Fore.RED + "[ERR]" + Fore.WHITE + f" nmap not installed. Please install nmap and try again.\nTracelog:\n{e}")
        return
    
    try:
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + " Starting scan on network " + Fore.GREEN + f"{network}" + Fore.WHITE + " with ports " + Fore.GREEN + f"{ports}..." + Fore.WHITE)
        nm.scan(hosts=f'{network}', arguments=f'-sV -p {ports} -T4', timeout=120)
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + " Scan completed.")
    except Exception as e:
        print(Fore.RED + "[nmap]" + Fore.WHITE + f" Error during scanning: {e}")
        return

    try:
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Connecting to Database...")
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database']
        )
        cursor = conn.cursor()
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Database connection established.")
    except Exception as e:
        print(Fore.YELLOW + "[db]" + Fore.WHITE + f" Error: {e}")
        return

    try:
        if nm.all_hosts():
            found_hosts = set()

            for host in nm.all_hosts():
                print(Fore.YELLOW + "[nmap]" + Fore.WHITE + f" Found device: " + Fore.CYAN + f"{host}")

                status = nm[host].state()
                device_info = {
                    'hostname': nm[host].hostname(),
                    'ports': []
                }

                for proto in nm[host].all_protocols():
                    port_list = nm[host][proto].keys()
                    for port in port_list:
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
                        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Updated information about " + Fore.GREEN + f"{host}" + Fore.WHITE + "")
                else:
                    cursor.execute(
                        "INSERT INTO scans (ip, status, device_info) VALUES (%s, %s, %s)",
                        (host, status, device_info_json)
                    )
                    print(Fore.YELLOW + "[db]" + Fore.WHITE + " Inserted information about " + Fore.GREEN + f"{host}" + Fore.WHITE + "")

                found_hosts.add(host)

            cursor.execute("SELECT ip FROM scans")
            all_hosts = cursor.fetchall()
            for (ip,) in all_hosts:
                if ip not in found_hosts:
                    cursor.execute(
                        "UPDATE scans SET status = 'down' WHERE ip = %s",
                        (ip,)
                    )
                    # print(f"Set status to 'down' for {ip}")

            conn.commit()
            print(Fore.YELLOW + "[db]" + Fore.WHITE + " Database updated successfully.")
        else:
            print(Fore.YELLOW + "[nmap]" + Fore.WHITE + " No hosts found in the network.")
    except Exception as e:
        print(Fore.RED + f"[ERR] An error occurred: {e}")
    finally:
        cursor.close()
        conn.close()
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Connection closed.")


if __name__ == "__main__":
    try:
        network = input("Enter the network to scan " + Fore.CYAN + "(e.g., 192.168.1.0/24): " + Fore.WHITE +"")
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        exit(0)

    try:
        ports = input("Enter the ports to scan " + Fore.CYAN + "(e.g., 22,80,443): " + Fore.WHITE +"")
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        exit(0)

    try:
        interval = input("Scan interval (minutes)  " + Fore.CYAN + "(e.g., 1): " + Fore.WHITE +"")
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        exit(0)

    try:
        while True:
            scan_network(network, ports)
            if float(interval) >= 1:
                print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {interval} minutes before next scan...")
            else:
                print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {float(interval) * 60} seconds before next scan...")
            
            time.sleep(float(interval) * 60)
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
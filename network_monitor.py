import nmap
import pymysql
import json
import time
from colorama import Fore
from config import DB_CONFIG, VENV, FLASK_CONFIG, SCAN_CONFIG
import subprocess
import os
import getpass

# Global variables to manage the API process state
process = None
api_started = False

class DatabaseConnection:
    """Context manager for database connection."""
    def __init__(self):
        self.connection = None
        self.cursor = None

    def __enter__(self):
        self.connection = pymysql.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database']
        )
        self.cursor = self.connection.cursor()
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Database connection established.")
        return self.cursor

    def __exit__(self, exc_type, exc_value, traceback):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Connection closed.")

def start_api():
    """Starts the REST API using a subprocess."""
    global process, api_started
    try:
        python_executable = os.path.join(VENV['PATH'], 'Scripts', 'python.exe')
        with open(os.devnull, 'w') as devnull:
            process = subprocess.Popen([python_executable, 'rest_api.py'], stdout=devnull, stderr=devnull)
            print(Fore.YELLOW + "[API]" + Fore.WHITE + " REST API started at " + Fore.CYAN + f"http://{FLASK_CONFIG['HOST']}:{FLASK_CONFIG['PORT']}/api/scans" + Fore.WHITE)
        api_started = True
    except Exception as e:
        print(Fore.RED + "[ERR]" + Fore.WHITE + f" Failed to start 'rest_api.py'. {e}")
        api_started = False

def get_user_input(prompt, default_value=None):
    """Helper function to get user input with exception handling and default value."""
    try:
        user_input = input(prompt)
        return user_input if user_input else default_value
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        return None
    except EOFError:
        print("\nEnd of file reached. Exiting...")
        return None

def terminate_api():
    """Terminates the API process if it's running."""
    global api_started
    if api_started:
        try:
            process.terminate()
            process.wait()
            time.sleep(5)
            print(Fore.YELLOW + "[API]" + Fore.WHITE + " REST API process terminated.")
            api_started = False
        except KeyboardInterrupt:
            print(Fore.RED + "[ERR]" + Fore.WHITE + " Failed to terminate the API process.")

def scan_network(network, ports):
    """Scans the specified network for devices and updates the database."""
    nm = initialize_nmap()
    if not nm:
        return
    
    if not perform_scan(nm, network, ports):
        return
    
    with DatabaseConnection() as cursor:
        process_scan_results(nm, cursor)

def initialize_nmap():
    """Initializes the nmap PortScanner."""
    try:
        return nmap.PortScanner()
    except Exception as e:
        print(Fore.RED + "[ERR]" + Fore.WHITE + " nmap not installed. Please install nmap and try again.\nTracelog:\n{e}")
        return None

def perform_scan(nm, network, ports):
    """Performs the network scan."""
    try:
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + f" Starting scan on network {Fore.GREEN}{network}{Fore.WHITE} with ports {Fore.GREEN}{ports}...")
        nm.scan(hosts=network, arguments=f'-sV -p {ports} -T4', timeout=120)
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + " Scan completed.")
        return True
    except Exception as e:
        print(Fore.RED + "[nmap]" + Fore.WHITE + f" Error during scanning: {e}")
        return False

def process_scan_results(nm, cursor):
    """Processes the results of the network scan and updates the database."""
    found_hosts = set()

    for host in nm.all_hosts():
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + f" Found device: " + Fore.CYAN + f"{host}")
        status = nm[host].state()
        device_info_json = get_device_info_json(nm, host)

        # Check if the device is already in the database
        cursor.execute("SELECT device_info FROM scans WHERE ip = %s", (host,))
        result = cursor.fetchone()

        if result:
            update_device_info(cursor, status, device_info_json, host, result[0])
        else:
            insert_device_info(cursor, status, device_info_json, host)

        found_hosts.add(host)

    update_device_status(cursor, found_hosts)
    cursor.connection.commit()  # Commit the changes to the database
    print(Fore.YELLOW + "[db]" + Fore.WHITE + " Database updated successfully.")

def get_device_info_json(nm, host):
    """Collects device information and returns it as a JSON string."""
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

    return json.dumps(device_info)

def update_device_info(cursor, status, device_info_json, host, existing_info):
    """Updates existing device information in the database."""
    if existing_info != device_info_json:
        cursor.execute(
            "UPDATE scans SET status = %s, device_info = %s, timestamp = CURRENT_TIMESTAMP WHERE ip = %s",
            (status, device_info_json, host)
        )
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Updated information about " + Fore.GREEN + f"{host}")

def insert_device_info(cursor, status, device_info_json, host):
    """Inserts new device information into the database."""
    cursor.execute(
        "INSERT INTO scans (ip, status, device_info) VALUES (%s, %s, %s)",
        (host, status, device_info_json)
    )
    print(Fore.YELLOW + "[db]" + Fore.WHITE + " Inserted information about " + Fore.GREEN + f"{host}")

def update_device_status(cursor, found_hosts):
    """Updates the status of devices that were not found in the current scan."""
    cursor.execute("SELECT ip FROM scans")
    all_hosts = cursor.fetchall()
    for (ip,) in all_hosts:
        if ip not in found_hosts:
            cursor.execute(
                "UPDATE scans SET status = 'down' WHERE ip = %s",
                (ip,)
            )

def configure_settings():
    """Function to configure database and other settings."""
    print(Fore.YELLOW + "[Config]" + Fore.WHITE + " Configure your settings:")
    
    db_host = get_user_input("Database Host (default: localhost): ", "localhost")
    db_user = get_user_input("Database User (default: root): ", "root")
    
    db_password = getpass.getpass("Database Password (default: password): ") or "password"
    
    db_name = get_user_input("Database Name (default: network_monitoring): ", "network_monitoring")
    
    venv_path = get_user_input("Virtual Environment Path (default: .\\venv): ", ".\\venv")
    flask_host = get_user_input("Flask Host (default: 0.0.0.0): ", "0.0.0.0")
    flask_port = int(get_user_input("Flask Port (default: 5000): ", "5000"))
    
    flask_debug_input = get_user_input("Flask Debug (default: True): ", "True")
    flask_debug = flask_debug_input.lower() in ['true', '1', 'yes']
    
    default_network = get_user_input("Default Network to Scan (default: 192.168.1.0/24): ", "192.168.1.0/24")
    default_ports = get_user_input("Default Ports to Scan (default: 22,80,443): ", "22,80,443")
    default_interval = float(get_user_input("Default Scan Interval (minutes, default: 1): ", "1"))

    config_data = {
        "DB_CONFIG": {
            "host": db_host,
            "user": db_user,
            "password": db_password,
            "database": db_name
        },
        "VENV": {
            "PATH": venv_path
        },
        "FLASK_CONFIG": {
            "HOST": flask_host,
            "PORT": flask_port,
            "DEBUG": flask_debug
        },
        "SCAN_CONFIG": {
            "DEFAULT_NETWORK": default_network,
            "DEFAULT_PORTS": default_ports,
            "DEFAULT_INTERVAL": default_interval
        }
    }

    # Сохраняем конфигурацию в config.py
    with open('config.py', 'w') as config_file:
        config_file.write("DB_CONFIG = ")
        config_file.write(json.dumps(config_data["DB_CONFIG"], indent=4))
        config_file.write("\n\n")
        config_file.write("VENV = ")
        config_file.write(json.dumps(config_data["VENV"], indent=4))
        config_file.write("\n\n")
        config_file.write("FLASK_CONFIG = ")
        # Записываем DEBUG как True/False
        config_file.write(f"{{'HOST': '{flask_host}', 'PORT': {flask_port}, 'DEBUG': {str(flask_debug).capitalize()}}}\n")
        config_file.write("\nSCAN_CONFIG = ")
        config_file.write(json.dumps(config_data["SCAN_CONFIG"], indent=4))

    print(Fore.GREEN + "[Config]" + Fore.WHITE + " Configuration saved to config.py.")

if __name__ == "__main__":
    try:
        while True:
            choice = get_user_input("Choose an option:\n1. Configure\n2. Scan\nEnter your choice: ", "2")
            if choice is None:
                break
            if choice == "1":
                configure_settings()
            elif choice == "2":
                start_api()  # Start the API
                network = get_user_input("Enter the network to scan " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_NETWORK']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_NETWORK']}")
                ports = get_user_input("Enter the ports to scan " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_PORTS']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_PORTS']}")
                interval = float(get_user_input("Scan interval (minutes)  " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_INTERVAL']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_INTERVAL']}"))

                try:
                    while True:
                        scan_network(network, ports)  # Perform the network scan
                        wait_time = float(interval) * 60
                        if interval < 1:
                            print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time} seconds before next scan...")
                        else:
                            print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time / 60} minutes before next scan...")
                        time.sleep(wait_time)  # Wait for the specified interval before the next scan
                except KeyboardInterrupt:
                    print("\nScan interrupted by user. Exiting...")
                    terminate_api()  # Terminate the API process if running
            else:
                print(Fore.RED + "[ERR]" + Fore.WHITE + " Invalid choice. Please enter 1 or 2.")
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")
    finally:
        terminate_api()  # Terminate the API process if running
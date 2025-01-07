#-----------------#
# Imported modules
import nmap                                                         # Import the nmap library for network scanning
import pymysql                                                      # Import pymysql for interacting with MySQL databases
import json                                                         # Import json for working with JSON data
import time                                                         # Import time for time-related functions
from colorama import Fore                                           # Import Fore from colorama for colored terminal text
import config as config                                             # Import the config module for configuration settings
from config import DB_CONFIG, VENV, FLASK_CONFIG, SCAN_CONFIG       # Import configuration settings from the config module
import subprocess                                                   # Import subprocess for executing shell commands
import os                                                           # Import os for operating system dependent functionality
import sys                                                          # Import sys for system-specific parameters and functions
import getpass                                                      # Import getpass for securely getting user passwords without echoing
import socket                                                       # Import the socket library for network communication
import random                                                       # Import the random library for generating random numbers
import hashlib                                                      # Import the hashlib library for hashing (e.g., generating MD5 hashes)
import argparse                                                     # Import argparse for parsing command-line arguments
from art import *                                                   # Import everything from the art library for ASCII art generation
import importlib                                                    # Import importlib for importing modules dynamically
import speedtest                                                    # Import the speedtest library for testing internet speed
from getmac import get_mac_address                                  # Import get_mac_address to retrieve MAC addresses of devices
from datetime import datetime                                       # Import datetime for working with dates and times
import ipaddress                                                    # Import ipaddress for working with IP addresses
from tqdm import tqdm                                               # Import tqdm for progress bars

#-----------------#
# Global variables to manage the API process state
process = None          # Global variable to hold the reference to the API process
api_started = False     # Global flag to indicate whether the API has been started
current_date = datetime.now().strftime("%Y.%m.%d")
log_file_path = f'logs/flask_{current_date}.log'

#-----------------#
# Function to clear the console screen based on the operating system.
def clear_console():
    # Check OS
    if sys.platform.startswith('win'):  # Windows
        os.system('cls')
    else:                               # Unix/Linux/MacOS
        os.system('clear')

#-----------------#
# Context manager for managing database connections.
class DatabaseConnection:
    def __init__(self):
        # Initialize connection and cursor as None
        self.connection = None
        self.cursor = None

    def __enter__(self):
        importlib.reload(config)
        DB_CONFIG = config.DB_CONFIG
        # Establishes a database connection and returns the cursor for executing queries.
        try:
            # Create a new database connection using pymysql
            self.connection = pymysql.connect(
                host=DB_CONFIG['host'],
                user=DB_CONFIG['user'],
                password=DB_CONFIG['password'],
                database=DB_CONFIG['database'],
                charset='utf8mb4'
            )
            # Create a cursor object to interact with the database
            self.cursor = self.connection.cursor()
            tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Database connection established.")
            if self.cursor:
                return self.cursor      # Return the cursor for use in the with statement
        except pymysql.err.OperationalError as e:
            tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error: unable to connect to the database: {e}")
            return None                 # Return None to indicate the connection failed
        except UnicodeEncodeError:
            # Handle the case where the password cannot be encoded
            tqdm.write(Fore.RED + "[db]" + Fore.WHITE + " Error: unable to encode password")
        except Exception as e:
            tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" An error occurred: {e}")
            return None                 # Return None to indicate the connection failed

    def __exit__(self, exc_type, exc_value, traceback):
        # Closes the database connection and cursor when exiting the context.
        if self.cursor:
            self.cursor.close()         # Close the cursor if it exists
        if self.connection:
            self.connection.close()     # Close the database connection if it exists
        tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Connection closed.")

#-----------------#
# Initializes the database and the scans table if they do not exist.
def initialize_database(cursor):
    try:
        tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Checking MySQL status...")
        cursor.execute("SHOW DATABASES;")  # Run a simple request to verify the connection
        if cursor:
            tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " MySQL is running.")
            # Check if the database exists
            tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Cheking database...")
            cursor.execute("SHOW DATABASES LIKE 'network_monitoring'")
            result = cursor.fetchone()

            if not result:
                # Create the database if it does not exist
                cursor.execute("CREATE DATABASE network_monitoring")
                tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Database 'network_monitoring' created.")
            else:
                tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Database 'network_monitoring' exists.")

            # Switch to the network_monitoring database
            try:
                cursor.execute("USE network_monitoring")
            except Exception as e:
                tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error: {e}")


            tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Cheking database table...")
            # Check if the scans table exists
            try:
                cursor.execute("SHOW TABLES LIKE 'scans'")
                result = cursor.fetchone()

                if not result:
                    # Create the scans table if it does not exist
                    cursor.execute("""
                        CREATE TABLE scans (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            ip VARCHAR(15),
                            status VARCHAR(10),
                            device_info JSON,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP() ON UPDATE CURRENT_TIMESTAMP(),
                            domain VARCHAR(100) DEFAULT 'None',
                            mac_address VARCHAR(50) DEFAULT 'None',
                            network VARCHAR(18) DEFAULT 'None'
                        )
                    """)
                    tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Table 'scans' created in 'network_monitoring' database.")
                else:
                    tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Table 'scans' exists.")
            except Exception as e:
                tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error: {e}")
            # If the request is successful, exit the loop
    except pymysql.err.OperationalError:
        tqdm.write(Fore.RED + "[db]" + Fore.WHITE + " MySQL is not available. Retrying in 5 seconds...")
        time.sleep(5)  # Wait 5 seconds before trying again
    except Exception as e:
        tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error initializing database: {e}")

#-----------------#
# Speedtest.
def spd_test():
    # Perform a speed test to measure download and upload speeds, as well as ping.
    try:
        st = speedtest.Speedtest()  # Create an instance of the Speedtest class

        ds = st.download()          # Measure download speed
        us = st.upload()            # Measure upload speed
        st.get_servers([])          # Retrieve the list of servers (empty list means use default)
        ping = st.results.ping      # Get the ping result

        tqdm.write(Fore.GREEN + "[Speedtest]" + Fore.WHITE + f" Download speed: {humansize(ds)}")    # Print the download speed in a human-readable format
        tqdm.write(Fore.GREEN + "[Speedtest]" + Fore.WHITE + f" Upload speed: {humansize(us)}")      # Print the upload speed in a human-readable format
        tqdm.write(Fore.GREEN + "[Speedtest]" + Fore.WHITE + f" Ping: {ping} ms")                    # Print the ping result in milliseconds
    except Exception as e:
        tqdm.write(Fore.RED + "[Speedtest]" + Fore.WHITE + f" Error: {e}")                           # Print an error message if an exception occurs during the speed test

def humansize(nbytes):
    """
    Convert a number of bytes into a human-readable format (e.g., KB, MB, GB).

    Parameters:
        nbytes (int): The number of bytes to convert.

    Returns:
        str: A string representing the size in a human-readable format.
    """

    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']  # List of size suffixes
    i = 0                                           # Initialize index for suffixes
    # Loop to divide the number of bytes by 1024 until it is less than 1024
    while nbytes >= 1024 and i < len(suffixes) - 1:
        nbytes /= 1024.0                            # Divide by 1024 to convert to the next size
        i += 1                                      # Increment the index for the suffixes

    f = ('%.2f' % nbytes).rstrip('0').rstrip('.')   # Format the number to two decimal places and remove trailing zeros
    return '%s %s' % (f, suffixes[i])               # Return the formatted size with the appropriate suffix

#-----------------#
# Get data for logfile
def get_log_file():
    global current_date, log_file_path
    new_date = datetime.now().strftime("%Y.%m.%d")
    if new_date != current_date:
        current_date = new_date
        log_file_path = f'logs/flask_{current_date}.log'
    return log_file_path

#-----------------#
# Starts the REST API as a subprocess.
def start_api():
    # Declare global variables to be used in the function
    global process, api_started

    try:
        # Construct the path to the Python executable in the virtual environment
        if sys.platform.startswith('win'):
            python_executable = os.path.join(VENV['PATH'], 'Scripts', 'python.exe')
        else:
            python_executable = os.path.join(VENV['PATH'], 'bin', 'python')

        if not os.path.exists('logs'):
            os.makedirs('logs')  # Create the logs directory

        # current_date = datetime.now().strftime("%Y.%m.%d")
        # log_file_path = f'logs/flask_{current_date}.log'
        # Open the log file for writing
        with open(get_log_file(), 'a') as log_file:
            # Start the REST API as a subprocess, redirecting stdout and stderr to the log file
            process = subprocess.Popen(
                [python_executable, 'app/rest_api.py'],
                stdout=log_file,
                stderr=log_file
            )
            tqdm.write(Fore.YELLOW + "[API]" + Fore.WHITE + " REST API started at " + Fore.CYAN + f"http://{FLASK_CONFIG['HOST']}:{FLASK_CONFIG['PORT']}" + Fore.WHITE)

        api_started = True      # Set the api_started flag to True indicating the API has started
        return 0
    except Exception as e:
        tqdm.write(Fore.RED + "[ERR]" + Fore.WHITE + f" Failed to start 'rest_api.py'. {e}")
        api_started = False     # Set the api_started flag to False indicating the API did not start
        return 1

#-----------------#
# Helper function to prompt the user for input with exception handling.
def get_user_input(prompt, default_value=None):
    try:
        user_input = input(prompt)                              # Prompt the user for input
        return user_input if user_input else default_value      # Return the user input if it's provided; otherwise, return the default value
    except KeyboardInterrupt:
        # Handle the case where the user interrupts the input (Ctrl+C)
        tqdm.write("\nInterrupted by user. Exiting...")
        return None                                             # Return None to indicate the operation was interrupted
    except EOFError:
        # Handle the case where an end-of-file is reached (Ctrl+D)
        tqdm.write("\nEnd of file reached. Exiting...")
        return None                                             # Return None to indicate the operation was interrupted

#-----------------#
# Terminates the running API process if it is active.
def terminate_api():
    # Declare global variable to track the API status
    global api_started
    # Check if the API is currently running
    if api_started:
        try:
            process.terminate()     # Terminate the API process
            process.wait()          # Wait for the process to terminate completely
            time.sleep(5)           # Sleep for a short duration to ensure the process has fully terminated
            tqdm.write(Fore.YELLOW + "[API]" + Fore.WHITE + " REST API process terminated.")
            api_started = False     # Set the api_started flag to False to indicate the API is no longer running
            return 0
        except KeyboardInterrupt:
            # Handle the case where the termination is interrupted by the user
            tqdm.write(Fore.RED + "[ERR]" + Fore.WHITE + " Failed to terminate the API process.")
            return 1

#-----------------#
# Parses the network range string and generates a list of individual networks.
def parse_network_range(network_range):
    networks = []
    # Split the ranges by space
    for net in network_range.split():
        net = net.strip()
        # Split into parts by dots
        parts = net.split('.')

        # Generate all possible combinations for each octet
        def generate_addresses(parts, index):
            if index == len(parts):
                # If we reached the end, form the address
                networks.append('.'.join(parts))
                return

            if '-' in parts[index]:
                # If there is a range, split it
                start, end = map(int, parts[index].split('-'))
                for i in range(start, end + 1):
                    parts[index] = str(i)
                    generate_addresses(parts, index + 1)
                parts[index] = f"{start}-{end}"  # Restore the range
            else:
                # If there is no range, just continue
                generate_addresses(parts, index + 1)
        generate_addresses(parts, 0)
    return networks

#-----------------#
# Scans the specified network for devices and updates the database with the results.
def scan_network(network_range, ports, no_progressbar=False):
    # Generate all networks from the range
    networks = parse_network_range(network_range)

    total_hosts = len(networks)
    if no_progressbar:
        for network in networks:
            nm = initialize_nmap()  # Initialize nmap
            if not nm:
                return
            # Perform scanning for each network
            if not perform_scan(nm, network, ports):
                return

            with DatabaseConnection() as cursor:
                process_scan_results(nm, cursor, network, None)  # No progress bar

    else:
        with tqdm(total=total_hosts, desc=f"{Fore.CYAN}Scanning", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]" + Fore.WHITE, ncols=100, leave=True) as pbar:
            for network in networks:
                nm = initialize_nmap()  # Initialize nmap
                if not nm:
                    return
                # Perform scanning for each network
                if not perform_scan(nm, network, ports):
                    return

                with DatabaseConnection() as cursor:
                    process_scan_results(nm, cursor, network, pbar)  # Passing the current network

                pbar.update(1)

#-----------------#
# Initializes and returns an nmap PortScanner instance.
def initialize_nmap():
    # Try to create an instance of the Nmap PortScanner
    try:
        return nmap.PortScanner()       # Return the PortScanner instance if successful
    except Exception as e:
        # Handle the case where Nmap is not installed or another error occurs
        tqdm.write(Fore.RED + "[ERR]" + Fore.WHITE + f" nmap not installed. Please install nmap and try again.\nTracelog:\n{e}")
        return None                     # Return None to indicate that initialization failed

#-----------------#
# Performs the network scan on the specified network and ports.
def perform_scan(nm, network, ports):
    # Attempt to perform a network scan using the provided Nmap instance
    try:
        tqdm.write(Fore.YELLOW + "[nmap]" + Fore.WHITE + f" Starting scan on network {Fore.GREEN}{network}{Fore.WHITE} with ports {Fore.GREEN}{ports}{Fore.WHITE}...")
        # Execute the scan with version detection, specified ports, and a fast timing template
        nm.scan(hosts=network, arguments=f'-sV -p {ports} -T5 --unprivileged', timeout=1200)

        tqdm.write(Fore.YELLOW + "[nmap]" + Fore.WHITE + " Scan completed.")
        return True     # Return True to indicate the scan was successful
    except Exception as e:
        # Print an error message if an exception occurs during the scan
        tqdm.write(Fore.RED + "[nmap]" + Fore.WHITE + f" Error during scanning: {e}")
        return False    # Return False to indicate the scan failed

def normalize_device_info(device_info):
    """
    Normalizes device information to a consistent format.

    Args:
        device_info (str): A string containing device information in JSON format.

    Returns:
        str: A normalized string with device information in JSON format.
    """
    # Deserialize the JSON string into a dictionary
    device_info_dict = json.loads(device_info)

    # Sort keys and create a new dictionary
    normalized_info = {
        "hostname": device_info_dict.get("hostname", ""),
        "ports": sorted(device_info_dict.get("ports", []), key=lambda x: x['port'])
    }
    # Serialize back to a string with sorted keys
    return json.dumps(normalized_info, sort_keys=True)

#-----------------#
# Processes scan results and updates the database with device information.
def process_scan_results(nm, cursor, network, pbar):
    # Check if the database cursor is available
    if cursor is None:
        tqdm.write(Fore.RED + "[db]" + Fore.WHITE + " No database cursor available. Exiting process scan results.")
        return

    found_hosts = set()  # Initialize a set to keep track of found hosts

    # Iterate through all hosts found in the network scan
    for host in nm.all_hosts():
        status = nm[host].state()  # Get the current state of the host
        device_info_json, _ = get_device_info_json(nm, host)  # Retrieve device information in JSON format

        # Get the network address from the provided network
        network_address = str(ipaddress.ip_network(f"{network}", strict=False).network_address)
        tqdm.write(Fore.YELLOW + "[network]" + Fore.WHITE + f" Network address: {Fore.GREEN}{network_address}")
        pbar.refresh()
        try:
            # Attempt to get the MAC address of the host
            mac_address = get_mac_address(ip=host)
            if mac_address:
                tqdm.write(Fore.YELLOW + "[mac]" + Fore.WHITE + f" Found MAC address {Fore.GREEN}{mac_address}{Fore.WHITE} for host {Fore.GREEN}{host}")
                pbar.refresh()
            else:
                tqdm.write(Fore.YELLOW + "[mac]" + Fore.WHITE + f" MAC address for the host {Fore.GREEN}{host}{Fore.WHITE} was not found")
                mac_address = "None"  # Set MAC address to None if not found
                pbar.refresh()

            try:
                # Attempt to get the domain name associated with the host
                addr = socket.gethostbyaddr(host)
                address = addr[0]  # Get the domain name
                tqdm.write(Fore.YELLOW + "[socket]" + Fore.WHITE + f"Found domain name {Fore.GREEN}{addr[0]}{Fore.WHITE} on host {Fore.GREEN}{host}{Fore.WHITE}")
                pbar.refresh()
            except:
                address = "None"  # Set address to None if not found
                tqdm.write(Fore.YELLOW + "[socket]" + Fore.WHITE + f" No domain name found on host {Fore.GREEN}{host}")
                pbar.refresh()

            # Check if the device already exists in the database
            cursor.execute("SELECT device_info FROM scans WHERE ip = %s", (host,))
            result = cursor.fetchone()  # Fetch the result

            if result:
                # Update existing device information in the database
                update_device_info(cursor, status, device_info_json, host, address, result[0], network_address, mac_address)
            else:
                # Insert new device information into the database
                insert_device_info(cursor, status, device_info_json, host, address, network_address, mac_address)

            found_hosts.add(host)  # Add the host to the found hosts set
            pbar.refresh()

        except Exception as e:
            tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error: {e}")  # Print any errors encountered
            pbar.refresh()

    try:
        network_address = str(ipaddress.ip_network(f"{network}", strict=False).network_address)
        # Update the status of devices in the database
        update_device_status(cursor, found_hosts, network_address)
        cursor.connection.commit()  # Commit the changes to the database
        tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Database updated successfully.")
        pbar.refresh()
    except Exception as e:
        tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error updating device status: {e}")  # Print any errors encountered during update
        pbar.refresh()

#-----------------#
# Collects device information and returns it as a JSON string.
def get_device_info_json(nm, host):
    # Initialize a dictionary to store device information
    device_info = {
        'hostname': nm[host].hostname(),    # Get the hostname of the device
        'ports': []                         # Initialize an empty list to store port information
    }

    ports_status = []                       # Initialize a list to store the status of the ports

    # Iterate over all protocols available for the host
    for proto in nm[host].all_protocols():
        port_list = nm[host][proto].keys()  # Get the list of ports for the current protocol
        # Iterate over each port in the port list
        for port in port_list:
            # Create a dictionary to store information about the port
            port_info = {
                'port': port,                                           # Port number
                'state': nm[host][proto][port]['state'],                # State of the port (open, closed, filtered)
                'name': nm[host][proto][port]['name'],                  # Name of the service running on the port
                'product': nm[host][proto][port].get('product', ''),    # Product name (if available)
                'version': nm[host][proto][port].get('version', '')     # Version of the product (if available)
            }
            # Append the port information to the device_info dictionary
            device_info['ports'].append(port_info)

            # Append the port status to the ports_status list with color coding
            if port_info['state'] == 'open':
                ports_status.append(Fore.GREEN + str(port))     # Open ports in green
            elif port_info['state'] == 'filtered':
                ports_status.append(Fore.YELLOW + str(port))    # Open ports in green
            elif port_info['state'] == 'closed':
                ports_status.append(Fore.RED + str(port))       # Closed portsprocess_scan_data in red

    ports_status_str = ','.join(ports_status)           # Join the port status list into a single string

    return json.dumps(device_info), ports_status_str    # Return the device information as a JSON string and the port status string

#-----------------#
# Updates existing device information in the database if it has changed.
def insert_device_info(cursor, status, device_info_json, host, address, network_address, mac_address):
    # Attempt to insert device information into the database
    try:
        cursor.execute(
            "INSERT INTO scans (ip, status, device_info, domain, mac_address, network) VALUES (%s, %s, %s, %s, %s, %s)",
            (host, status, device_info_json, address, mac_address, network_address)
        )
        # Print a success message indicating the device information was inserted
        tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Inserted information about " + Fore.GREEN + f"{host}")
        cursor.connection.commit()  # Commit the transaction to the database
    except Exception as e:
        # Print an error message if an exception occurs
        tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error: {e}")

def update_device_info(cursor, status, device_info_json, host, address, existing_info, network_address, mac_address):
    # Check if the normalized device information has changed
    if normalize_device_info(device_info_json) != normalize_device_info(existing_info):
        # Attempt to update device information in the database
        try:
            cursor.execute(
                "UPDATE scans SET status = %s, device_info = %s, timestamp = CURRENT_TIMESTAMP, domain = %s, mac_address = %s, network = %s WHERE ip = %s",
                (status, device_info_json, address, mac_address, network_address, host)
            )
            # Print a success message indicating the device information was updated
            tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Updated information about " + Fore.GREEN + f"{host}")
            cursor.connection.commit()  # Commit the transaction to the database
        except Exception as e:
            # Print an error message if an exception occurs
            tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error: {e}")
    else:
        # Print a message indicating no changes were detected
        tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " No changes detected for " + Fore.GREEN + f"{host}")

#-----------------#
# Updates the status of devices that were not found in the current scan.
def update_device_status(cursor, found_hosts, network_address):
    # Execute an SQL SELECT statement to retrieve all IP addresses from the scans table
    tqdm.write(Fore.YELLOW + f"Updating status for network {Fore.GREEN}{network_address}{Fore.WHITE}...")
    try:
        cursor.execute("SELECT ip FROM scans WHERE network = %s", (network_address,))
        all_hosts = cursor.fetchall()       # Fetch all results from the executed query
    except Exception as e:
        tqdm.write(Fore.RED + "[db]" + Fore.WHITE + " Error retrieving all hosts: " + str(e))
        return None

    # Iterate over each IP address retrieved from the database
    for (ip,) in all_hosts:
        # Check if the current IP address is not in the list of found hosts
        if ip not in found_hosts:
            # Execute an SQL UPDATE statement to set the status of the device to 'down'
            cursor.execute(
                "UPDATE scans SET status = 'down' WHERE ip = %s",
                (ip,)                   # Parameter for the SQL query
            )

#-----------------#
# Configures database and other settings based on user input.
def configure_settings(db_host=None, db_user=None, db_password=None, db_name=None, flask_host=None, flask_port=None, flask_debug=None, default_network=None, default_ports=None, default_interval=None, spd_test=None):
    # If the parameters are not passed, request from the user
    if db_host is None:
        tqdm.write(Fore.YELLOW + "[Config]" + Fore.WHITE + " Configure your settings:")
        db_host = get_user_input(f"Database Host (default: {DB_CONFIG['host']}): ", f"{DB_CONFIG['host']}")
    if db_user is None:
        db_user = get_user_input(f"Database User (default: {DB_CONFIG['user']}): ", f"{DB_CONFIG['user']}")
    if db_password is None:
        db_password = getpass.getpass("Database Password (default: mysecretpassword): ") or "mysecretpassword"
    if db_name is None:
        db_name = get_user_input(f"Database Name (default: {DB_CONFIG['database']}): ", f"{DB_CONFIG['database']}")
    if flask_host is None:
        flask_host = get_user_input(f"Flask Host (default: {FLASK_CONFIG['HOST']}): ", f"{FLASK_CONFIG['HOST']}")
    if flask_port is None:
        flask_port = int(get_user_input(f"Flask Port (default: {FLASK_CONFIG['PORT']}): ", f"{FLASK_CONFIG['PORT']}"))
    if flask_debug is None:
        flask_debug_input = get_user_input(f"Flask Debug (default: {FLASK_CONFIG['DEBUG']}): ", f"{FLASK_CONFIG['DEBUG']}")
        flask_debug = flask_debug_input.lower() in ['true', '1', 'yes']

    # Prompt for default scan values
    if default_network is None:
        tqdm.write(Fore.GREEN + "Default values: " + Fore.WHITE)
        default_network = get_user_input(f"Default Network to Scan (default: {SCAN_CONFIG['DEFAULT_NETWORK']}): ", f"{SCAN_CONFIG['DEFAULT_NETWORK']}")
    if default_ports is None:
        default_ports = get_user_input(f"Default Ports to Scan (default: {SCAN_CONFIG['DEFAULT_PORTS']}): ", f"{SCAN_CONFIG['DEFAULT_PORTS']}")
    if default_interval is None:
        default_interval = float(get_user_input(f"Default Scan Interval (minutes, default: {SCAN_CONFIG['DEFAULT_INTERVAL']}): ", f"{SCAN_CONFIG['DEFAULT_INTERVAL']}"))
    if spd_test is None:
        spd_test_input = get_user_input(f"Speedtest before scan (default: {SCAN_CONFIG['SPD_TEST']}): ", f"{SCAN_CONFIG['SPD_TEST']}")
        spd_test = spd_test_input.lower() in ['true', '1', 'yes']

    # Compile all configuration data into a dictionary
    config_data = {
        "DB_CONFIG": {
            "host": db_host,
            "user": db_user,
            "password": db_password,
            "database": db_name
        },
        "VENV": {
            "PATH": VENV["PATH"],
            "API_KEY": VENV["API_KEY"],
            "VERSION": VENV["VERSION"]
        },
        "FLASK_CONFIG": {
            "HOST": flask_host,
            "PORT": flask_port,
            "DEBUG": flask_debug
        },
        "SCAN_CONFIG": {
            "DEFAULT_NETWORK": default_network,
            "DEFAULT_PORTS": default_ports,
            "DEFAULT_INTERVAL": default_interval,
            "SPD_TEST": spd_test
        }
    }

    # Write the configuration data to config.py
    with open('app/config.py', 'w') as config_file:
        config_file.write("import os\n\n")
        config_file.write("DB_CONFIG = ")
        config_file.write(json.dumps(config_data["DB_CONFIG"], indent=4))
        config_file.write("\n\n")
        config_file.write("VENV = {\n")
        config_file.write(f"    'PATH': os.path.join('.', 'venv'),\n")
        config_file.write(f"    'API_KEY': '',\n")
        config_file.write(f"    'VERSION': '{config_data['VENV']['VERSION']}'\n")
        config_file.write("}\n\n")
        config_file.write("FLASK_CONFIG = ")
        config_file.write(f"{{'HOST': '{flask_host}', 'PORT': {flask_port}, 'DEBUG': {str(flask_debug).capitalize()}}}\n")
        config_file.write("\nSCAN_CONFIG = ")
        config_file.write(f"{{\n    'DEFAULT_NETWORK': '{default_network}',\n    'DEFAULT_PORTS': '{default_ports}',\n    'DEFAULT_INTERVAL': {default_interval},\n    'SPD_TEST': {str(spd_test).capitalize()}\n}}\n")

    tqdm.write(Fore.GREEN + "[Config]" + Fore.WHITE + " Configuration saved to config.py.")
    tqdm.write(Fore.GREEN + "[API]" + Fore.WHITE + " API available at http://" + flask_host + ":" + str(flask_port) + "/")
    generate_api_key()

#-----------------#
# Generate Api Key (MD5)
def generate_api_key():
    importlib.reload(config)

    random_number = random.randint(100000000, 999999999)  # Generate a random 9-digit number
    api_key_string = f".netmonitor_{random_number}_config."  # Form the string for the key
    api_key = hashlib.md5(api_key_string.encode()).hexdigest()  # Calculate the MD5 hash
    tqdm.write(Fore.CYAN + "=============================================================" + Fore.WHITE)
    tqdm.write(Fore.GREEN + "[API Key]" + Fore.WHITE + " Generated API Key: " + Fore.CYAN + f"{api_key}" + Fore.WHITE)
    tqdm.write(Fore.CYAN + "============================================================="  + Fore.WHITE)

    # Load the existing config.py
    config_data = {}
    with open('app/config.py', 'r') as config_file:
        exec(config_file.read(), config_data)  # Execute the code to get the variables

    # Update API_KEY in VENV

    # Save the updated config back to config.py
    with open('app/config.py', 'w') as config_file:
        config_file.write("import os\n\n")
        config_file.write("DB_CONFIG = ")
        config_file.write(json.dumps(config_data["DB_CONFIG"], indent=4))  # Write DB_CONFIG
        config_file.write("\n\n")
        config_file.write("VENV = {\n")
        config_file.write(f"    'PATH': os.path.join('.', 'venv'),\n")
        config_file.write(f"    'API_KEY': '{api_key}',\n")
        config_file.write(f"    'VERSION': '{config_data['VENV']['VERSION']}'\n")
        config_file.write("}\n\n")
        config_file.write("FLASK_CONFIG = {\n")
        config_file.write(f"    'HOST': '{config_data['FLASK_CONFIG']['HOST']}',\n")
        config_file.write(f"    'PORT': {config_data['FLASK_CONFIG']['PORT']},\n")
        config_file.write(f"    'DEBUG': {str(config_data['FLASK_CONFIG']['DEBUG']).capitalize()}\n")  # Write DEBUG correctly
        config_file.write("}\n\n")
        config_file.write("SCAN_CONFIG = {\n")
        config_file.write(f"    'DEFAULT_NETWORK': '{config_data['SCAN_CONFIG']['DEFAULT_NETWORK']}',\n")
        config_file.write(f"    'DEFAULT_PORTS': '{config_data['SCAN_CONFIG']['DEFAULT_PORTS']}',\n")
        config_file.write(f"    'DEFAULT_INTERVAL': {config_data['SCAN_CONFIG']['DEFAULT_INTERVAL']},\n")
        config_file.write(f"    'SPD_TEST': {str(config_data['SCAN_CONFIG']['SPD_TEST']).capitalize()}\n")
        config_file.write("}")

    tqdm.write(Fore.GREEN + "[Config]" + Fore.WHITE + " API Key saved to config.py.")

if __name__ == "__main__":
    # Creating a Command Line Argument parser
    parser = argparse.ArgumentParser(description=f'Network Monitor v{VENV["VERSION"]}')

    # Adding mutually exclusive group for scan and config
    exclusive_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_group.add_argument('--config', action='store_true', help='Run configuration')
    exclusive_group.add_argument('--scan', action='store_true', help='Run scan')

    # Disable progress bar argument
    parser.add_argument('--no-progressbar', action='store_true', help='Disable progress bar')

    # Group for scan arguments
    scan_group = parser.add_argument_group('Scan Arguments')
    scan_group.add_argument('--network', type=str, help='Network to scan')
    scan_group.add_argument('--ports', type=str, help='Ports to scan')
    scan_group.add_argument('--interval', type=float, help='Scan interval in minutes')

    # Group for configuration arguments
    config_group = parser.add_argument_group('Configuration Arguments')
    config_group.add_argument('--db_host', type=str, help='Database Host')
    config_group.add_argument('--db_user', type=str, help='Database User')
    config_group.add_argument('--db_password', type=str, help='Database Password')
    config_group.add_argument('--db_name', type=str, help='Database Name')
    config_group.add_argument('--flask_host', type=str, help='Flask Host')
    config_group.add_argument('--flask_port', type=int, help='Flask Port')
    config_group.add_argument('--flask_debug', type=bool, help='Flask Debug (True/False)')
    config_group.add_argument('--default_network', type=str, help='Default Network')
    config_group.add_argument('--default_ports', type=str, help='Default ports')
    config_group.add_argument('--default_interval', type=float, help='Default interval')
    config_group.add_argument('--spd_test', type=bool, help='Speedtest before scan')


    # Parsing arguments
    args = parser.parse_args()

    # Check for mutually exclusive arguments
    if args.config and args.scan:
        tqdm.write(Fore.RED + "[Error]" + Fore.WHITE + " You cannot use --config and --scan together.")
        exit(1)

    # If configuration arguments are provided
    if args.config:
        # Check if all required configuration arguments are provided
        if not all([args.db_host, args.db_user, args.db_password, args.db_name, args.flask_host, args.flask_port, args.flask_debug]):
            tqdm.write(Fore.RED + "[Error]" + Fore.WHITE + " Missing required configuration arguments.")
            exit(1)

        logo = text2art(
            '''NetworkMonitor
            by DekimDev''', "colossal"
        )
        tqdm.write(Fore.CYAN + logo + Fore.WHITE)
        tqdm.write(Fore.CYAN + "-------------" + Fore.WHITE)
        tqdm.write(Fore.GREEN + "Version " + VENV["VERSION"] + Fore.WHITE)
        tqdm.write(Fore.CYAN + "-------------" + Fore.WHITE)
        tqdm.write("")
        tqdm.write(Fore.YELLOW + "[Info]" + Fore.WHITE + " Starting configuration with provided parameters...")
        try:
            # Ensure SPD_TEST is capitalized
            spd_test_value = str(args.spd_test).capitalize() if args.spd_test is not None else None

            configure_settings(args.db_host, args.db_user, args.db_password, args.db_name, args.flask_host, args.flask_port, args.flask_debug, args.default_network, args.default_ports, args.default_interval, spd_test_value)
            tqdm.write(Fore.YELLOW + "[db]" + Fore.WHITE + " Creating database if not exist...")
            with DatabaseConnection() as cursor:
                importlib.reload(config)
                DB_CONFIG = config.DB_CONFIG
                VENV = config.VENV
                FLASK_CONFIG = config.FLASK_CONFIG
                SCAN_CONFIG = config.SCAN_CONFIG
                initialize_database(cursor)  # Initialize the database and table
            tqdm.write(Fore.GREEN + "[EXIT]" + Fore.WHITE + f" Configurator exited with code 0")
            exit(0)
        except Exception as e:
            tqdm.write(Fore.RED + "[Error]" + Fore.WHITE + f" An error occurred during configuration: {e}")
            tqdm.write(Fore.RED + "[EXIT]" + Fore.WHITE + f" Configurator exited with code 1")
            exit(1)

    # If scan arguments are provided
    if args.scan:
        # Check if all required scan arguments are provided
        if not all([args.network, args.ports, args.interval]):
            tqdm.write(Fore.RED + "[Error]" + Fore.WHITE + " Missing required scan arguments.")
            exit(1)

        tqdm.write(Fore.YELLOW + "[Info]" + Fore.WHITE + " Starting scan with provided parameters...")
        start_api()  # Launching the API
        try:
            # Use a database connection to initialize the database and table
            try:
                if SCAN_CONFIG["SPD_TEST"]:
                    tqdm.write(Fore.YELLOW + "[Speedtest]" + Fore.WHITE + " Checking the connection speed...")
                    spd_test()
                with DatabaseConnection() as cursor:
                    importlib.reload(config)
                    DB_CONFIG = config.DB_CONFIG
                    VENV = config.VENV
                    FLASK_CONFIG = config.FLASK_CONFIG
                    SCAN_CONFIG = config.SCAN_CONFIG
                    initialize_database(cursor)  # Initialize the database and table
            except pymysql.err.OperationalError as e:
                tqdm.write(Fore.RED + "[db]" + Fore.WHITE + f" Error: unable to connect to the database: {e}")

            while True:
                scan_network(args.network, args.ports, args.no_progressbar)  # Performing a network scan
                wait_time = args.interval * 60  # We calculate the waiting time in seconds
                if args.interval < 1:
                    tqdm.write(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time} seconds before next scan...")
                else:
                    tqdm.write(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time / 60} minutes before next scan...")
                time.sleep(wait_time)  # Waiting for the specified time before the next scan
        except KeyboardInterrupt:
            tqdm.write(Fore.YELLOW + "\nScan interrupted by user. Exiting...")
            terminate_api()  # Completing the API process if it is running

    # Handle case where no valid arguments are provided
    if not args.config and not args.scan:

        # Start of the main program execution
        try:
            clear_console()
            tqdm.write("")
            logo = text2art(
                '''NetworkMonitor
                by DekimDev''', "colossal"
            )
            tqdm.write(Fore.CYAN + logo + Fore.WHITE)
            tqdm.write(Fore.CYAN + "-------------" + Fore.WHITE)
            tqdm.write(Fore.GREEN + "Version " + VENV["VERSION"] + Fore.WHITE)
            tqdm.write(Fore.CYAN + "-------------" + Fore.WHITE)
            tqdm.write("")
            # Infinite loop to continuously prompt the user for an action
            while True:
                # Get user input for choosing an option (configure or scan)
                choice = get_user_input("Choose an option:\n" + Fore.GREEN + "1. " + Fore.WHITE + "Configure\n" + Fore.GREEN + "2. " + Fore.WHITE + "Scan\n" + Fore.GREEN + "3. " + Fore.WHITE + "Generate/Regenerate API Key\n" + Fore.GREEN + "4. " + Fore.WHITE + "SpeedTest\n" + Fore.GREEN + "5. " + Fore.WHITE + "Exit\nEnter your choice: ", "2")
                if choice is None:
                    break                   # Exit the loop if no choice is made
                # If the user chooses to configure settings
                if choice == "1":
                    configure_settings()
                    importlib.reload(config)
                    DB_CONFIG = config.DB_CONFIG
                    VENV = config.VENV
                    FLASK_CONFIG = config.FLASK_CONFIG
                    SCAN_CONFIG = config.SCAN_CONFIG
                # If the user chooses to start scanning
                elif choice == "2":
                    start_api()             # Start the API
                    # Get network details from the user with default values
                    network = get_user_input("Enter the network to scan " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_NETWORK']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_NETWORK']}")
                    ports = get_user_input("Enter the ports to scan " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_PORTS']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_PORTS']}")
                    interval = float(get_user_input("Scan interval (minutes)  " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_INTERVAL']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_INTERVAL']}"))

                    try:
                        if SCAN_CONFIG["SPD_TEST"]:
                            tqdm.write(Fore.YELLOW + "[Speedtest]" + Fore.WHITE + " Checking the connection speed...")
                            spd_test()

                        # Infinite loop to perform scanning at specified intervals
                        while True:
                            scan_network(network, ports, args.no_progressbar)        # Perform the network scan
                            wait_time = float(interval) * 60    # Calculate wait time in seconds
                            if interval < 1:
                                tqdm.write(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time} seconds before next scan...")
                            else:
                                tqdm.write(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time / 60} minutes before next scan...")
                            time.sleep(wait_time)               # Wait for the specified interval before the next scan
                    except KeyboardInterrupt:
                        # Handle the case where the scan is interrupted by the user
                        tqdm.write(Fore.YELLOW + "\nScan interrupted by user. Exiting...")
                        terminate_api()                         # Terminate the API process if running
                elif choice == "3":
                    generate_api_key()
                elif choice == "4":
                    tqdm.write(Fore.YELLOW + "============================================" + Fore.WHITE)
                    tqdm.write(Fore.YELLOW + "[Speedtest]" + Fore.WHITE + " Checking the connection speed...")
                    spd_test()
                    tqdm.write(Fore.YELLOW + "============================================" + Fore.WHITE)
                elif choice == "5":
                    tqdm.write(Fore.YELLOW + "Exiting..." + Fore.WHITE)
                    exit()
                else:
                    # Handle invalid user input
                    tqdm.write(Fore.RED + "[ERR]" + Fore.WHITE + " Invalid choice. Please enter 1-5.")
        except KeyboardInterrupt:
            # Handle the case where the program is interrupted by the user
            tqdm.write("\nProgram interrupted by user. Exiting...")
        finally:
            # Ensure the API process is terminated when exiting the program
            terminate_api()     # Terminate the API process if running
#-----------------#
# Imported modules
import nmap                                                         # Import the nmap library for network scanning
import pymysql                                                      # Import pymysql for interacting with MySQL databases
import json                                                         # Import json for working with JSON data
import time                                                         # Import time for time-related functions
from colorama import Fore                                           # Import Fore from colorama for colored terminal text
from config import DB_CONFIG, VENV, FLASK_CONFIG, SCAN_CONFIG       # Import configuration settings from the config module
import subprocess                                                   # Import subprocess for executing shell commands
import os                                                           # Import os for operating system dependent functionality
import sys
import getpass                                                      # Import getpass for securely getting user passwords without echoing
import socket
import random
import hashlib
import argparse

#-----------------#
# Global variables to manage the API process state
process = None          # Global variable to hold the reference to the API process
api_started = False     # Global flag to indicate whether the API has been started

#-----------------#
# Context manager for managing database connections.
class DatabaseConnection:

    def __init__(self):
        # Initialize connection and cursor as None
        self.connection = None
        self.cursor = None

    def __enter__(self):
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
            print(Fore.YELLOW + "[db]" + Fore.WHITE + " Database connection established.")
            if self.cursor:
                return self.cursor      # Return the cursor for use in the with statement
        except pymysql.err.OperationalError as e:
            print(Fore.RED + "[db]" + Fore.WHITE + f" Error: unable to connect to the database: {e}")
            return None  # Return None to indicate the connection failed
        except UnicodeEncodeError:
            # Handle the case where the password cannot be encoded
            print(Fore.RED + "[db]" + Fore.WHITE + " Error: unable to encode password")
        except Exception as e:
            print(Fore.RED + "[db]" + Fore.WHITE + f" An error occurred: {e}")
            return None  # Return None to indicate the connection failed

    def __exit__(self, exc_type, exc_value, traceback):
        # Closes the database connection and cursor when exiting the context.
        if self.cursor:
            self.cursor.close()         # Close the cursor if it exists
        if self.connection:
            self.connection.close()     # Close the database connection if it exists
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Connection closed.")

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
        
        # Open a null device to suppress output
        with open(os.devnull, 'w') as devnull:
            # Start the REST API as a subprocess, redirecting stdout and stderr to devnull
            process = subprocess.Popen([python_executable, 'rest_api.py'], stdout=devnull, stderr=devnull)
            print(Fore.YELLOW + "[API]" + Fore.WHITE + " REST API started at " + Fore.CYAN + f"http://{FLASK_CONFIG['HOST']}:{FLASK_CONFIG['PORT']}" + Fore.WHITE)
        api_started = True      # Set the api_started flag to True indicating the API has started
        return 0
    except Exception as e:
        print(Fore.RED + "[ERR]" + Fore.WHITE + f" Failed to start 'rest_api.py'. {e}")
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
        print("\nInterrupted by user. Exiting...")
        return None                                             # Return None to indicate the operation was interrupted
    except EOFError:
        # Handle the case where an end-of-file is reached (Ctrl+D)
        print("\nEnd of file reached. Exiting...")
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
            print(Fore.YELLOW + "[API]" + Fore.WHITE + " REST API process terminated.")
            api_started = False     # Set the api_started flag to False to indicate the API is no longer running
            return 0
        except KeyboardInterrupt:
            # Handle the case where the termination is interrupted by the user
            print(Fore.RED + "[ERR]" + Fore.WHITE + " Failed to terminate the API process.")
            return 1
#-----------------#
# Scans the specified network for devices and updates the database with the results.
def scan_network(network, ports):
    nm = initialize_nmap()      # Initialize the Nmap scanner

    # Check if the Nmap scanner was initialized successfully
    if not nm:
        return                  # Exit the function if initialization failed
    
    # Perform the network scan with the specified parameters
    if not perform_scan(nm, network, ports):
        return                  # Exit the function if the scan was not successful
    
    # Use a database connection to process the scan results
    with DatabaseConnection() as cursor:
        process_scan_results(nm, cursor)    # Process and store the scan results in the database
    return 0
#-----------------#
# Initializes and returns an nmap PortScanner instance.
def initialize_nmap():
    # Try to create an instance of the Nmap PortScanner
    try:
        return nmap.PortScanner()       # Return the PortScanner instance if successful
    except Exception as e:
        # Handle the case where Nmap is not installed or another error occurs
        print(Fore.RED + "[ERR]" + Fore.WHITE + f" nmap not installed. Please install nmap and try again.\nTracelog:\n{e}")
        return None                     # Return None to indicate that initialization failed

#-----------------#
# Performs the network scan on the specified network and ports.
def perform_scan(nm, network, ports):
    # Attempt to perform a network scan using the provided Nmap instance
    try:
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + f" Starting scan on network {Fore.GREEN}{network}{Fore.WHITE} with ports {Fore.GREEN}{ports}...")
        # Execute the scan with version detection, specified ports, and a fast timing template
        nm.scan(hosts=network, arguments=f'-sV -p {ports} -T5 --unprivileged', timeout=1200)
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + " Scan completed.")
        return True     # Return True to indicate the scan was successful
    except Exception as e:
        # Print an error message if an exception occurs during the scan
        print(Fore.RED + "[nmap]" + Fore.WHITE + f" Error during scanning: {e}")
        return False    # Return False to indicate the scan failed

#-----------------#
# Processes scan results and updates the database with device information.
def process_scan_results(nm, cursor):
    if cursor is None:
        print(Fore.RED + "[db]" + Fore.WHITE + " No database cursor available. Exiting process scan results.")
        return  # Exit the function if cursor is None
    
    # Initialize a set to keep track of found hosts
    found_hosts = set()

    # Iterate over all hosts found in the Nmap scan results
    for host in nm.all_hosts():
        status = nm[host].state()       # Get the current state of the host (up or down)
        # Retrieve device information and port status as a JSON string
        device_info_json, ports_status_str = get_device_info_json(nm, host)
        print(Fore.YELLOW + "[nmap]" + Fore.WHITE + f" Found device: " + Fore.CYAN + f"{host} | " + Fore.WHITE + f"Ports: [{ports_status_str}" + Fore.WHITE + "]")
        try:    
            addr = socket.gethostbyaddr(host)
            address = addr[0]
            print(Fore.YELLOW + "[socket]" + Fore.WHITE + f"Found domain name {addr[0]} on host {host}")
        except:
            address = "None"
            print(Fore.YELLOW + "[socket]" + Fore.WHITE + f"No domain name found on host {host}")
        
        # Check if the device is already in the database
        try:
            cursor.execute("SELECT device_info FROM scans WHERE ip = %s", (host,))
            result = cursor.fetchone()
        except Exception as e:
            print(Fore.RED + "[db]" + Fore.WHITE + f" Error checking database for existing device: {e}")
            return None

        # If the device exists in the database, update its information
        if result:
            update_device_info(cursor, status, device_info_json, host, result[0], address)
        # If the device does not exist, insert new device information
        else:
            insert_device_info(cursor, status, device_info_json, host, address)

        found_hosts.add(host)           # Add the host to the set of found hosts

    update_device_status(cursor, found_hosts)   # Update the status of all found hosts in the database
    cursor.connection.commit()                  # Commit the changes to the database
    print(Fore.YELLOW + "[db]" + Fore.WHITE + " Database updated successfully.")

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
                ports_status.append(Fore.RED + str(port))       # Closed ports in red
    
    ports_status_str = ','.join(ports_status)           # Join the port status list into a single string

    return json.dumps(device_info), ports_status_str    # Return the device information as a JSON string and the port status string

#-----------------#
# Updates existing device information in the database if it has changed.
def update_device_info(cursor, status, device_info_json, host, existing_info, address):
    # Check if the existing device information is different from the new information
    if existing_info != device_info_json:
        # Execute an SQL UPDATE statement to update the device's status and information in the database
        try:
            cursor.execute(
                "UPDATE scans SET status = %s, device_info = %s, timestamp = CURRENT_TIMESTAMP, domain = %s WHERE ip = %s",
                (status, device_info_json, address, host)    # Parameters for the SQL query
            )
            print(Fore.YELLOW + "[db]" + Fore.WHITE + " Updated information about " + Fore.GREEN + f"{host}")
            cursor.connection.commit()
        except Exception as e:
            print(Fore.RED + "[db]" + Fore.WHITE + f" Error: {e}")


#-----------------#
# Inserts new device information into the database.
def insert_device_info(cursor, status, device_info_json, host, address):
    # Execute an SQL INSERT statement to add a new device's information to the database
    try:
        cursor.execute(
            "INSERT INTO scans (ip, status, device_info, domain) VALUES (%s, %s, %s, %s)",
            (host, status, device_info_json, address)        # Parameters for the SQL query
        )
        print(Fore.YELLOW + "[db]" + Fore.WHITE + " Inserted information about " + Fore.GREEN + f"{host}")
        cursor.connection.commit()
    except Exception as e:
        print(Fore.RED + "[db]" + Fore.WHITE + f" Error: {e}")


#-----------------#
# Updates the status of devices that were not found in the current scan.
def update_device_status(cursor, found_hosts):
    # Execute an SQL SELECT statement to retrieve all IP addresses from the scans table
    try:
        cursor.execute("SELECT ip FROM scans")
        all_hosts = cursor.fetchall()       # Fetch all results from the executed query
    except Exception as e:
        print(Fore.RED + "[db]" + Fore.WHITE + " Error retrieving all hosts: " + str(e))
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
def configure_settings(db_host=None, db_user=None, db_password=None, db_name=None, venv_path=None, flask_host=None, flask_port=None, flask_debug=None, default_network=None, default_ports=None, default_interval=None):
    

    random_number = random.randint(100000000, 999999999)  # Generate a random 9-digit number
    api_key_string = f".netmonitor_{random_number}_config."  # Form the string for the key
    api_key = hashlib.md5(api_key_string.encode()).hexdigest()  # Calculate the MD5 hash

    # If the parameters are not passed, request from the user
    if db_host is None:
        print(Fore.YELLOW + "[Config]" + Fore.WHITE + " Configure your settings:")
        db_host = get_user_input(f"Database Host (default: {DB_CONFIG['host']}): ", f"{DB_CONFIG['host']}")
    if db_user is None:
        db_user = get_user_input(f"Database User (default: {DB_CONFIG['user']}): ", f"{DB_CONFIG['user']}")
    if db_password is None:
        db_password = getpass.getpass("Database Password (default: password): ") or "password"
    if db_name is None:
        db_name = get_user_input(f"Database Name (default: {DB_CONFIG['database']}): ", f"{DB_CONFIG['database']}")
    if venv_path is None:
        venv_path = get_user_input(f"Virtual Environment Path (default: {VENV['PATH']}): ", f"{VENV['PATH']}")
    if flask_host is None:
        flask_host = get_user_input(f"Flask Host (default: {FLASK_CONFIG['HOST']}): ", f"{FLASK_CONFIG['HOST']}")
    if flask_port is None:
        flask_port = int(get_user_input(f"Flask Port (default: {FLASK_CONFIG['PORT']}): ", f"{FLASK_CONFIG['PORT']}"))
    if flask_debug is None:
        flask_debug_input = get_user_input(f"Flask Debug (default: {FLASK_CONFIG['DEBUG']}): ", f"{FLASK_CONFIG['DEBUG']}")
        flask_debug = flask_debug_input.lower() in ['true', '1', 'yes']
        
    # Prompt for default scan values
    if default_network is None:
        print(Fore.GREEN + "Default values: " + Fore.WHITE)
        default_network = get_user_input(f"Default Network to Scan (default: {SCAN_CONFIG['DEFAULT_NETWORK']}): ", f"{SCAN_CONFIG['DEFAULT_NETWORK']}")
    if default_ports is None:
        default_ports = get_user_input(f"Default Ports to Scan (default: {SCAN_CONFIG['DEFAULT_PORTS']}): ", f"{SCAN_CONFIG['DEFAULT_PORTS']}")
    if default_interval is None:
        default_interval = float(get_user_input(f"Default Scan Interval (minutes, default: {SCAN_CONFIG['DEFAULT_INTERVAL']}): ", f"{SCAN_CONFIG['DEFAULT_INTERVAL']}"))

    # Compile all configuration data into a dictionary
    config_data = {
        "DB_CONFIG": {
            "host": db_host,
            "user": db_user,
            "password": db_password,
            "database": db_name
        },
        "VENV": {
            "PATH": venv_path,
            "API_KEY": api_key
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

    # Write the configuration data to config.py
    with open('config.py', 'w') as config_file:
        config_file.write("DB_CONFIG = ")
        config_file.write(json.dumps(config_data["DB_CONFIG"], indent=4))       # Write DB_CONFIG section
        config_file.write("\n\n")
        config_file.write("VENV = ")
        config_file.write(json.dumps(config_data["VENV"], indent=4))            # Write VENV section
        config_file.write("\n\n")
        config_file.write("FLASK_CONFIG = ")
        config_file.write(f"{{'HOST': '{flask_host}', 'PORT': {flask_port}, 'DEBUG': {str(flask_debug).capitalize()}}}\n")  # Write FLASK_CONFIG section
        config_file.write("\nSCAN_CONFIG = ")
        config_file.write(json.dumps(config_data["SCAN_CONFIG"], indent=4))     # Write SCAN_CONFIG section

    print(Fore.GREEN + "[Config]" + Fore.WHITE + " Configuration saved to config.py.")
    print(Fore.GREEN + "[API]" + Fore.WHITE + " API available at http://" + flask_host + ":" + str(flask_port) + "/")
    print(Fore.GREEN + "[Config]" + Fore.WHITE + " Yor API key is: " + Fore.YELLOW + api_key + Fore.WHITE)

#-----------------#
# Generate Api Key (MD5)
def generate_api_key():
    random_number = random.randint(100000000, 999999999)  # Generate a random 9-digit number
    api_key_string = f".netmonitor_{random_number}_config."  # Form the string for the key
    api_key = hashlib.md5(api_key_string.encode()).hexdigest()  # Calculate the MD5 hash
    print(Fore.GREEN + "[API Key]" + Fore.WHITE + " Generated API Key: " + Fore.CYAN + f"{api_key}" + Fore.WHITE)

    # Load the existing config.py
    config_data = {}
    with open('config.py', 'r') as config_file:
        exec(config_file.read(), config_data)  # Execute the code to get the variables

    # Update API_KEY in VENV
    config_data['VENV']["API_KEY"] = api_key

    # Save the updated config back to config.py
    with open('config.py', 'w') as config_file:
        config_file.write("DB_CONFIG = ")
        config_file.write(json.dumps(config_data["DB_CONFIG"], indent=4))  # Write DB_CONFIG
        config_file.write("\n\n")
        config_file.write("VENV = ")
        config_file.write(json.dumps(config_data["VENV"], indent=4))  # Write VENV
        config_file.write("\n\n")
        config_file.write("FLASK_CONFIG = {\n")
        config_file.write(f"    'HOST': '{config_data['FLASK_CONFIG']['HOST']}',\n")
        config_file.write(f"    'PORT': {config_data['FLASK_CONFIG']['PORT']},\n")
        config_file.write(f"    'DEBUG': {str(config_data['FLASK_CONFIG']['DEBUG']).capitalize()}\n")  # Write DEBUG correctly
        config_file.write("}\n\n")
        config_file.write("SCAN_CONFIG = ")
        config_file.write(json.dumps(config_data["SCAN_CONFIG"], indent=4))  # Write SCAN_CONFIG

    print(Fore.GREEN + "[Config]" + Fore.WHITE + " API Key saved to config.py.")

#-----------------#
# Main execution block to handle user input and initiate scanning or configuration.
if __name__ == "__main__":
    # Creating a Command Line Argument parser
    parser = argparse.ArgumentParser(description='Network Monitor')
    parser.add_argument('--network', type=str, help='Network to scan')
    parser.add_argument('--ports', type=str, help='Ports to scan')
    parser.add_argument('--interval', type=float, help='Scan interval in minutes')

    # Configuration args
    parser.add_argument('--db_host', type=str, help='Database Host')
    parser.add_argument('--db_user', type=str, help='Database User')
    parser.add_argument('--db_password', type=str, help='Database Password')
    parser.add_argument('--db_name', type=str, help='Database Name')
    parser.add_argument('--venv_path', type=str, help='Virtual Environment Path')
    parser.add_argument('--flask_host', type=str, help='Flask Host')
    parser.add_argument('--flask_port', type=int, help='Flask Port')
    parser.add_argument('--flask_debug', type=bool, help='Flask Debug (True/False)')
    parser.add_argument('--default_network', type=str, help='Default Network')
    parser.add_argument('--default_ports', type=str, help='Default ports')
    parser.add_argument('--default_interval', type=float, help='Default interval')

    # Parsing arguments
    args = parser.parse_args()

    # If the parameters are set, run the scan
    if args.network and args.ports and args.interval:
        print(Fore.YELLOW + "[Info]" + Fore.WHITE + " Starting scan with provided parameters...")
        start_api()  # Launching the API
        try:            
            while True:
                scan_network(args.network, args.ports)  # Performing a network scan
                wait_time = args.interval * 60  # We calculate the waiting time in seconds
                if args.interval < 1:
                    print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time} seconds before next scan...")
                else:
                    print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time / 60} minutes before next scan...")
                time.sleep(wait_time)  # Waiting for the specified time before the next scan
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nScan interrupted by user. Exiting...")
            terminate_api()  # Completing the API process if it is running
    elif args.db_host or args.db_user or args.db_password or args.db_name or args.venv_path or args.flask_host or args.flask_port or args.flask_debug:
        print(Fore.YELLOW + "[Info]" + Fore.WHITE + " Starting configuration with provided parameters...")
        if not VENV["API_KEY"]:
            try:
                configure_settings(args.db_host, args.db_user, args.db_password, args.db_name, args.venv_path, args.flask_host, args.flask_port, args.flask_debug, args.default_network, args.default_ports, args.default_interval)
                print(Fore.GREEN + "[EXIT]" + Fore.WHITE + f" Configurator exited with code 0")
                exit(0)
            except Exception as e:
                print(Fore.RED + "[Error]" + Fore.WHITE + f" An error occurred during configuration")
                print(Fore.RED + "[EXIT]" + Fore.WHITE + f" Configurator exited with code 1")
                exit(1)
            print(Fore.GREEN + "[EXIT]" + Fore.WHITE + f" Configurator exited with code 0")
            exit(0)
        print(Fore.GREEN + "[EXIT]" + Fore.WHITE + f" Configurator exited with code 0")
        exit(0)
    else:
        # Start of the main program execution
        try:
            # Use a database connection to initialize the database and table
            # Infinite loop to continuously prompt the user for an action
            while True:
                # Get user input for choosing an option (configure or scan)
                choice = get_user_input("Choose an option:\n" + Fore.GREEN + "1. " + Fore.WHITE + "Configure\n" + Fore.GREEN + "2. " + Fore.WHITE + "Scan\n" + Fore.GREEN + "3. " + Fore.WHITE + "Generate/Regenerate API Key\nEnter your choice: ", "2")
                if choice is None:
                    break                   # Exit the loop if no choice is made
                # If the user chooses to configure settings
                if choice == "1":
                    configure_settings()
                # If the user chooses to start scanning
                elif choice == "2":
                    start_api()             # Start the API
                    # Get network details from the user with default values
                    network = get_user_input("Enter the network to scan " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_NETWORK']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_NETWORK']}")
                    ports = get_user_input("Enter the ports to scan " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_PORTS']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_PORTS']}")
                    interval = float(get_user_input("Scan interval (minutes)  " + Fore.CYAN + f"(default: {SCAN_CONFIG['DEFAULT_INTERVAL']}): " + Fore.WHITE, f"{SCAN_CONFIG['DEFAULT_INTERVAL']}"))

                    try:
                        # Infinite loop to perform scanning at specified intervals
                        while True:
                            scan_network(network, ports)        # Perform the network scan
                            wait_time = float(interval) * 60    # Calculate wait time in seconds
                            if interval < 1:
                                print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time} seconds before next scan...")
                            else:
                                print(Fore.YELLOW + "[Info]" + Fore.WHITE + f" Waiting for {wait_time / 60} minutes before next scan...")
                            time.sleep(wait_time)               # Wait for the specified interval before the next scan
                    except KeyboardInterrupt:
                        # Handle the case where the scan is interrupted by the user
                        print(Fore.YELLOW + "\nScan interrupted by user. Exiting...")
                        terminate_api()                         # Terminate the API process if running
                elif choice == "3":
                    generate_api_key()
                else:
                    # Handle invalid user input
                    print(Fore.RED + "[ERR]" + Fore.WHITE + " Invalid choice. Please enter 1 or 2.")
        except KeyboardInterrupt:
            # Handle the case where the program is interrupted by the user
            print("\nProgram interrupted by user. Exiting...")
        finally:
            # Ensure the API process is terminated when exiting the program
            terminate_api()                                     # Terminate the API process if running
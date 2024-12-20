#-----------------#
# Imported modules
from flask import Flask, request, jsonify, send_from_directory, render_template   # Import Flask framework and related functions for building web applications
import pymysql                                          # Import pymysql for connecting to and interacting with MySQL databases
from config import DB_CONFIG, FLASK_CONFIG, VENV              # Import database and Flask configuration settings from the config module
import os                                               # Import os for interacting with the operating system (e.g., file paths, environment variables)
from flasgger import Swagger                            # Importing Swagger for API documentation
import json

app = Flask(__name__)   # Create an instance of the Flask application

app.config['SWAGGER'] = {
    'title':"NetworkMonitor API",               # Title of your API
    'version':"1.0.2",                          # Version of your API
    'termsOfService': '/ToS'                  # Terms of Servise (ToS)
}

swagger = Swagger(app)

def connect_to_db():
    # Connect to the MySQL database using the provided configuration settings
    return pymysql.connect(
        host=DB_CONFIG['host'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        database=DB_CONFIG['database']
    )

def get_scan_data():
    # Establish a connection to the MySQL database using configuration settings
    conn = connect_to_db()
    try:
        cursor = conn.cursor()      # Create a cursor object to interact with the database
        cursor.execute("SELECT * FROM scans ORDER BY id ASC")   # Execute a SQL query to retrieve all scan records ordered by id
        rows = cursor.fetchall()    # Fetch all results from the executed query
        cursor.close()              # Close the cursor to free up resources
        conn.close()                # Close the database connection
        return rows                 # Return the fetched scan data
    except Exception as e:
        print(f"Error: {e}")
        return None
    
def get_scan_data_by_ip(ip):
    # Function to retrieve scan data by IP address
    conn = connect_to_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE ip = %s", (ip,))  # Use a parameterized query for security
        row = cursor.fetchone()  # Get a single record by IP address
        return row  # Return the found record
    except Exception as e:
        print(f"Error: {e}")
        return None  # If an error occurs, return None
    finally:
        cursor.close()
        conn.close()  # Close the database connection

def update_or_create_scan(scan_data):
    # Function for updating an existing record or creating a new one.
    conn = connect_to_db()
    try:
        cursor = conn.cursor()
        # Check if a record with the same IP already exists
        cursor.execute("SELECT * FROM scans WHERE ip = %s", (scan_data[0][0],))
        row = cursor.fetchone()

        if row is not None:
            # Update existing record
            cursor.execute("UPDATE scans SET status = %s, device_info = %s, domain = %s WHERE ip = %s",
                           (scan_data[0][1], json.dumps(scan_data[0][2]), scan_data[0][3], scan_data[0][0]))
        else:
            # Create a new record
            cursor.execute("INSERT INTO scans (ip, status, device_info, domain) VALUES (%s, %s, %s, %s)",
                           (scan_data[0][0], scan_data[0][1], json.dumps(scan_data[0][2]), scan_data[0][3]))

        conn.commit()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_ports_by_ip(ip):
    conn = connect_to_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT device_info FROM scans WHERE ip = %s", (ip,))
        row = cursor.fetchone()
        if row:
            return json.loads(row[0])['ports']  # Предполагается, что device_info хранит JSON
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

@app.route('/')     # Define the route for the root URL of the application
def index():
    return '''
    <html>
        <head>
            <title>Network Monitor API</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/3.52.5/swagger-ui.css" />
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f8f9fa;
                    margin: 0;
                    padding: 20px;
                }
                h1 {
                    color: #333;
                }
                h2 {
                    color: #007bff;
                }
                p {
                    color: #555;
                    line-height: 1.5;
                }
                a {
                    color: #007bff;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                }
                .container {
                    max-width: 800px;
                    margin: auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to the Network Monitor API</h1>
                <p>This API allows you to monitor network scans and retrieve scan data.</p>
                <h2>API Documentation</h2>
                <p>For detailed API documentation, visit <a href="/apidocs">/apidocs</a>.</p>
                <h2>Available Endpoints</h2>
                <ul>
                    <li><strong>GET /api/scans</strong> - Retrieve a list of all scans.</li>
                    <li><strong>GET /api/scans/&lt;ip&gt;</strong> - Retrieve scan data for a specific IP address.</li>
                </ul>
            </div>
        </body>
    </html>
    '''

@app.route('/favicon.ico')      # Define the route for the favicon.ico file
def favicon():
    # Serve the favicon.ico file from the 'static' directory of the application
    return send_from_directory(os.path.join(app.root_path, 'static'),   # Construct the path to the 'static' directory
                               'favicon.ico',                           # Specify the favicon file to be served
                               mimetype='image/vnd.microsoft.icon')     # Set the MIME type for the favicon

@app.route('/ToS')  # Define a route for Terms of Service
def terms_of_service():
    return '''
    <html>
        <head>
            <title>Terms of Service</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f8f9fa;
                    margin: 0;
                    padding: 20px;
                }
                h1 {
                    color: #333;
                }
                h2 {
                    color: #007bff;
                }
                p {
                    color: #555;
                    line-height: 1.5;
                }
                .container {
                    max-width: 800px;
                    margin: auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Terms of Service</h1>
                <p>Welcome to our API. Please read these terms carefully before using our service.</p>
                <h2>1. Acceptance of Terms</h2>
                <p>By accessing or using the API, you agree to be bound by these terms.</p>
                <h2>2. Changes to Terms</h2>
                <p>We may modify these terms from time to time. We will notify you of any changes.</p>
                <h2>3. Usage Guidelines</h2>
                <p>You agree to use the API in compliance with all applicable laws.</p>
                <h2>4. Limitation of Liability</h2>
                <p>Our liability is limited to the maximum extent permitted by law.</p>
                <h2>5. Contact Information</h2>
                <p>If you have any questions about these terms, please contact us at <a href="mailto:dekim@dekimdev.ru">dekim@dekimdev.ru</a>.</p>
            </div>
        </body>
    </html>
    '''

# @app.route('/web')
# def web_interface():
#     return render_template('index.html')

@app.route('/api/scans/ports/<string:ip>', methods=['GET'])
def get_ports(ip):
    """
    Get port information by IP address
    ---
    parameters:
      - name: ip
        in: path
        type: string
        required: true
        description: The IP address to retrieve port information for
    responses:
      200:
        description: A list of ports for the specified IP address
        schema:
          type: array
          items:
            type: object
            properties:
              port:
                type: integer
                example: 22
              state:
                type: string
                example: "open"
              name:
                type: string
                example: "ssh"
              product:
                type: string
                example: "OpenSSH"
              version:
                type: string
                example: "6.6.0"
      404:
        description: Not found
      500:
        description: Internal server error
    """
    ports = get_ports_by_ip(ip)
    if ports is not None:
        return jsonify(ports)
    else:
        return jsonify({"error": "Not found"}), 404
    
@app.route('/api/scans/page/<int:page>', methods=['GET'])
def get_scans_paginated(page):
    """
    Get paginated scan data
    ---
    parameters:
      - name: page
        in: path
        type: integer
        required: true
        description: The page number to retrieve
    responses:
      200:
        description: A list of scans for the specified page
        schema:
          type: array
          items:
            type: array
            items:
              oneOf:
                - type: integer
                  example: 1
                - type: string
                  example: "192.168.0.1"
                - type: string
                  example: "up"
                - type: string
                  example: '{"ports": [{"name": "ssh", "port": 22, "state": "open", "product": "OpenSSH", "version": "6.6.0"}, {"name": "http", "port": 80, "state": "open", "product": "TP-LINK router http config", "version": ""}, {"name": "https", "port": 443, "state": "open", "product": "", "version": ""}], "hostname": "TPLINK"}'
                - type: string
                  example: "Sat, 30 Nov 2024 12:29:20 GMT"
                - type: string
                  example: "example.com"
                - type: string
                  example: "00:15:5d:7b:09:06"
      404:
        description: Not found
      500:
        description: Internal server error
    """
    data = get_scan_data()  # Получаем все данные
    per_page = 10  # Количество хостов на странице
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = data[start:end]  # Пагинация данных
    return jsonify(paginated_data)

@app.route('/api/scans', methods=['GET'])   # Define the route for the API endpoint to get scan data, allowing only GET requests
def get_scans():
    """
    Get scan data
    ---
    responses:
      200:
        description: A list of scans
        schema:
          type: array
          items:
            type: array
            items:
                oneOf:
                    - type: integer
                      example: 1
                    - type: string
                      example: "192.168.0.1"
                    - type: string
                      example: "up"
                    - type: string
                      example: '{"ports": [{"name": "ssh", "port": 22, "state": "open", "product": "OpenSSH", "version": "6.6.0"}, {"name": "http", "port": 80, "state": "open", "product": "TP-LINK router http config", "version": ""}, {"name": "https", "port": 443, "state": "open", "product": "", "version": ""}], "hostname": "TPLINK"}'
                    - type: string
                      example: "Sat, 30 Nov 2024 12:29:20 GMT"
                    - type: string
                      example: "example.com"
                    - type: string
                      example: "00:15:5d:7b:09:06"
      404:
        description: Not found
      500:
        description: Internal server error
    """
    data = get_scan_data()  # Call the function to retrieve scan data from the database
    # Return the scan data as a JSON response
    return jsonify(data)    # Convert the data to JSON format and send it as a response

@app.route('/api/scans/<string:ip>', methods=['GET'])  # Define the route for retrieving data by IP address
def get_scan_by_ip(ip):
    """
    Get scan data by IP address
    ---
    parameters:
      - name: ip
        in: path
        type: string
        required: true
        description: The IP address to retrieve scan data for
    responses:
      200:
        description: Scan data for the specified IP address
        schema:
          type: array
          items:
            oneOf:
                - type: integer
                  example: 1
                - type: string
                  example: "192.168.0.1"
                - type: string
                  example: "up"
                - type: string
                  example: '{"ports": [{"name": "ssh", "port": 22, "state": "open", "product": "OpenSSH", "version": "6.6.0"}, {"name": "http", "port": 80, "state": "open", "product": "TP-LINK router http config", "version": ""}, {"name": "https", "port": 443, "state": "open", "product": "", "version": ""}], "hostname": "TPLINK"}'
                - type: string
                  example: "Sat, 30 Nov 2024 12:29:20 GMT"
                - type: string
                  example: "example.com"
                - type: string
                  example: "00:15:5d:7b:09:06"
      404:
        description: Not found
      500:
        description: Internal server error
    """
    row = get_scan_data_by_ip(ip)  # Retrieve data by IP address

    if row is not None:  # If the record is found, return it
        return jsonify(row)
    else:  # If the record is not found or an error occurred
        if row is None:  # If an error occurred while retrieving data
            return jsonify({"error": "Internal server error"}), 500
        else:  # If the record is not found
            return jsonify({"error": "Not found"}), 404

@app.route('/api/scans', methods=['POST'])  # Определяем маршрут для POST-запроса
def create_or_update_scan():
    """
    Create a new scan or update an existing one
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: API token for authorization
      - name: scan_data
        in: body
        required: true
        schema:
          type: array
          items:
            type: array
            items:
                
                oneOf:
                    - type: string
                      description: "Ip address"
                      example: "192.168.0.1"
                    - type: string
                      description: "Device status"
                      example: "up"
                    - type: string
                      description: "Ports information"
                      example: '{"ports": [{"name": "ssh", "port": 22, "state": "open", "product": "OpenSSH", "version": "6.6.0"}, {"name": "http", "port": 80, "state": "open", "product": "TP-LINK router http config", "version": ""}, {"name": "https", "port": 443, "state": "open", "product": "", "version": ""}], "hostname": "TPLINK"}'
                    - type: string
                      description: "Domain name"
                      example: "example.com"
                    - type: string
                      description: "Mac Address"
                      example: "00:15:5d:7b:09:06"
                
    responses:
      201:
        description: Scan created or updated successfully
      401:
        description: Unauthorized
      400:
        description: Bad request
      500:
        description: Internal server error
    """
    # Проверка авторизации
    auth_header = request.headers.get('Authorization')
    if auth_header.__contains__("Bearer"):
        auth_header = auth_header.split("Bearer ")[1]
    print(f"Authorization header: {auth_header}")
    if not auth_header:
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header  # Извлекаем токен
    if token != VENV['API_KEY']:  # Сравниваем с ключом из конфигурации
        return jsonify({"error": "Unauthorized"}), 401

    # Получение данных из запроса
    scan_data = request.json
    print(f"Received scan_data: {scan_data}")
    if not isinstance(scan_data, list) or not all(isinstance(item, list) for item in scan_data):
        return jsonify({"error": "Bad request"}), 400

    # Обновление или создание записи
    if update_or_create_scan(scan_data):
        return jsonify({"message": "Scan created or updated successfully"}), 201
    else:
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # Start the Flask application with the specified configuration settings
    app.run(debug=FLASK_CONFIG['DEBUG'],    # Enable or disable debug mode based on the configuration
            host=FLASK_CONFIG['HOST'],      # Set the host address for the server
            port=FLASK_CONFIG['PORT'])      # Set the port number for the server
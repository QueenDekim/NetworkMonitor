#-----------------#
# Imported modules
from flask import Flask, jsonify, send_from_directory   # Import Flask framework and related functions for building web applications
import pymysql                                          # Import pymysql for connecting to and interacting with MySQL databases
from config import DB_CONFIG, FLASK_CONFIG              # Import database and Flask configuration settings from the config module
import os                                               # Import os for interacting with the operating system (e.g., file paths, environment variables)

app = Flask(__name__)   # Create an instance of the Flask application

def get_scan_data():
    # Establish a connection to the MySQL database using configuration settings
    conn = pymysql.connect(
            host=DB_CONFIG['host'],             # Database host
            user=DB_CONFIG['user'],             # Database user
            password=DB_CONFIG['password'],     # Database password
            database=DB_CONFIG['database']      # Database name
        )
    cursor = conn.cursor()      # Create a cursor object to interact with the database
    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")   # Execute a SQL query to retrieve all scan records ordered by timestamp
    rows = cursor.fetchall()    # Fetch all results from the executed query
    cursor.close()              # Close the cursor to free up resources
    conn.close()                # Close the database connection
    return rows                 # Return the fetched scan data

@app.route('/')     # Define the route for the root URL of the application
def index():
    return '''
    <html>
        <head>
            <title>Network Monitor API</title>
        </head>
        <body>
            <h1>Welcome to the Network Monitor API</h1>
            <p>Use <a href="/api/scans">/api/scans</a> to get scan data.</p>
        </body>
    </html>
    '''

@app.route('/favicon.ico')      # Define the route for the favicon.ico file
def favicon():
    # Serve the favicon.ico file from the 'static' directory of the application
    return send_from_directory(os.path.join(app.root_path, 'static'),   # Construct the path to the 'static' directory
                               'favicon.ico',                           # Specify the favicon file to be served
                               mimetype='image/vnd.microsoft.icon')     # Set the MIME type for the favicon


@app.route('/api/scans', methods=['GET'])   # Define the route for the API endpoint to get scan data, allowing only GET requests
def get_scans():
    data = get_scan_data()  # Call the function to retrieve scan data from the database
    # Return the scan data as a JSON response
    return jsonify(data)    # Convert the data to JSON format and send it as a response


if __name__ == '__main__':
    # Start the Flask application with the specified configuration settings
    app.run(debug=FLASK_CONFIG['DEBUG'],    # Enable or disable debug mode based on the configuration
            host=FLASK_CONFIG['HOST'],      # Set the host address for the server
            port=FLASK_CONFIG['PORT'])      # Set the port number for the server
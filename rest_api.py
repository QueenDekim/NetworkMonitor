from flask import Flask, jsonify
import mysql.connector

app = Flask(__name__)

def get_scan_data():
    conn = mysql.connector.connect(
        host='localhost',
        user='username',
        password='password',
        database='network_monitoring'
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

@app.route('/api/scans', methods=['GET']) 
def get_scans():
    data = get_scan_data()
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5150) 
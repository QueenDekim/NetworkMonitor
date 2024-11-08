from flask import Flask, jsonify
import pymysql
from config import DB_CONFIG, FLASK_CONFIG

app = Flask(__name__)

def get_scan_data():
    conn = pymysql.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database']
        )
    cursor = conn.cursor()
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
    app.run(debug=FLASK_CONFIG['DEBUG'], host=FLASK_CONFIG['HOST'], port=FLASK_CONFIG['PORT']) 
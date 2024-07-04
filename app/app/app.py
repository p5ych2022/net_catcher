from flask import Flask, jsonify, render_template, request
import mysql.connector
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def db_connection():
    return mysql.connector.connect(
        host="mariadb", 
        port=3306,
        user="ids",
        password="1ds",
        database="traffic_data",
        charset='utf8mb4',
        collation='utf8mb4_unicode_ci'
    )

def fetch_data_from_db(limit=100, offset=0, query=''):
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    search_query = f"%{query}%"
    query = """SELECT * FROM traffic 
               WHERE src_ip LIKE %s OR dst_ip LIKE %s OR protocol LIKE %s OR payload LIKE %s 
               ORDER BY timestamp DESC LIMIT %s OFFSET %s"""
    cursor.execute(query, (search_query, search_query, search_query, search_query, limit, offset))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data', methods=['GET'])
def get_data():
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    query = request.args.get('query', '', type=str)
    rows = fetch_data_from_db(limit, offset, query)
    return jsonify(rows)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT protocol, COUNT(*) as count FROM traffic GROUP BY protocol")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(rows)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

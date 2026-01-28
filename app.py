import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)

DB_PATH = "users.db"

def init_db():
    """Create DB if not exists (for Docker fresh build)."""
    if not os.path.exists(DB_PATH):
        db = sqlite3.connect(DB_PATH)
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                name TEXT,
                email TEXT
            )
        """)
        # Demo data
        cursor.execute("INSERT INTO users VALUES ('1', 'Alice', 'alice@example.com')")
        cursor.execute("INSERT INTO users VALUES ('2', 'Bob',   'bob@example.com')")
        db.commit()
        db.close()

def get_user_info(user_id):
    if not user_id:
        return None

    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()

    # ⚠ Intentional vulnerable query (SQLi for demo)
    query = "SELECT name, email FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

    data = cursor.fetchall()
    db.close()
    return data

@app.route('/user')
def show_user():
    user_id = request.args.get('id')
    info = get_user_info(user_id)

    if info and len(info) > 0:
        # Safely access name and email from first result
        name, email = info[0]
        return f"<h1>User Found:</h1><p>Name: {name}</p><p>Email: {email}</p>"

    return "<h1>User not found.</h1>"

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)

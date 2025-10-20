from flask import Flask, render_template, request, redirect, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret_key_ihgwkg86fwge7gwiy3efefef23fe3f'

DATABASE = 'database.sql'

def create_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            info TEXT,
            credits INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS faculty (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            info TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    # Render homepage

    return render_template('index.html')
    pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handle user login
    pass

@app.route('/logout')
def logout():
    # Handle user logout
    pass

@app.route('/new_account', methods=['GET', 'POST'])
def new_account():
    # Handle new account creation
    pass

@app.route('/student_edit', methods=['GET', 'POST'])
def student_edit():
    # Edit student information
    pass

@app.route('/faculty_update', methods=['GET', 'POST'])
def faculty_update():
    # Edit faculty information
    pass

create_database()
if __name__ == '__main__':
    app.run(debug=True)


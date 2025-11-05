from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret_key_ihgwkg86fwge7gwiy3efefef23fe3f'

DATABASE = 'database.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_database():
    conn = get_db_connection()
    c = conn.cursor()

    # login table (users)
    c.execute('''
        CREATE TABLE IF NOT EXISTS login (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # students table with required fields
    c.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            bluegoldID TEXT UNIQUE,
            name TEXT,
            address TEXT,
            phone TEXT,
            gpa REAL DEFAULT 0.0,
            total_credits INTEGER DEFAULT 0,
            balance REAL DEFAULT 0.0,
            updated_at TEXT
        )
    ''')

    # transactions / audit log
    c.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_username TEXT,
            action TEXT,
            details TEXT,
            timestamp TEXT
        )
    ''')

    conn.commit()

    # Seed a default faculty account if none exists
    c.execute("SELECT * FROM login WHERE role = 'faculty' LIMIT 1")
    if c.fetchone() is None:
        # default faculty: username=admin, password=adminpass
        hashed = generate_password_hash('adminpass')
        c.execute('INSERT INTO login (username, password, role) VALUES (?, ?, ?)',
                  ('admin', hashed, 'faculty'))
        conn.commit()
        c.execute('INSERT INTO transactions (actor_username, action, details, timestamp) VALUES (?, ?, ?, ?)',
                  ('system', 'seed', 'Created default faculty account `admin`', datetime.utcnow().isoformat()))
        conn.commit()

    conn.close()


def log_transaction(actor, action, details):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO transactions (actor_username, action, details, timestamp) VALUES (?, ?, ?, ?)',
              (actor, action, details, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def get_user(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM login WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    return row


def create_faculty_account(username: str, password: str, actor: str = 'system') -> bool:
    """Create a faculty account with the given username and password.

    Returns True on success, False if the username already exists.
    """
    if not username or not password:
        return False
    conn = get_db_connection()
    c = conn.cursor()
    try:
        hashed = generate_password_hash(password)
        c.execute('INSERT INTO login (username, password, role) VALUES (?, ?, ?)',
                  (username, hashed, 'faculty'))
        conn.commit()
        log_transaction(actor, 'create_faculty', f'Created faculty {username}')
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


@app.context_processor
def inject_user_role():
    # make user and role available to all templates as variables `user` and `role`
    return dict(user=session.get('user'), role=session.get('role'))


@app.route('/')
def index():
    user = session.get('user')
    role = session.get('role')
    return render_template('index.html', user=user, role=role)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, don't show the login page
    if session.get('user'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['role']
            log_transaction(username, 'login', 'Successful login')
            flash('Logged in successfully.', 'success')
            if user['role'] == 'faculty':
                return redirect(url_for('faculty_update'))
            else:
                return redirect(url_for('student_edit'))
        else:
            log_transaction(username if username else 'unknown', 'login_failed', 'Invalid credentials')
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    user = session.get('user')
    session.clear()
    if user:
        log_transaction(user, 'logout', 'User logged out')
    return redirect(url_for('index'))


@app.route('/new_account', methods=['GET', 'POST'])
def new_account():
    # Only faculty can create new student accounts via the web UI. Redirect students and unauthenticated users.
    if session.get('role') == 'student':
        flash('Students are not allowed to access the new account page', 'danger')
        return redirect(url_for('index'))
    if 'user' not in session:
        # Not logged in users should log in first
        return redirect(url_for('login'))
    if request.method == 'POST':
        # enforce only faculty can create student accounts
        if session.get('role') != 'faculty':
            flash('Only faculty can create new student accounts.', 'danger')
            return redirect(url_for('index'))

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip()
        bluegold = request.form.get('bluegoldID', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()

        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('new_account'))

        # Validate phone: must be exactly 10 digits
        if not phone.isdigit() or len(phone) != 10:
            flash('Phone number must be exactly 10 digits (numbers only).', 'danger')
            return redirect(url_for('new_account'))

        # Validate Bluegold ID: if provided, must be exactly 7 digits
        if bluegold:
            if not bluegold.isdigit() or len(bluegold) != 7:
                flash('Bluegold ID must be exactly 7 digits (numbers only).', 'danger')
                return redirect(url_for('new_account'))

        hashed = generate_password_hash(password)
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO login (username, password, role) VALUES (?, ?, ?)',
                      (username, hashed, 'student'))
            c.execute('INSERT INTO students (username, bluegoldID, name, phone, address, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
                      (username, bluegold, name, phone, address, datetime.utcnow().isoformat()))
            conn.commit()
            flash(f'Created student account {username}', 'success')
            log_transaction(session.get('user', 'unknown'), 'create_account', f'Created student {username}')
        except sqlite3.IntegrityError as e:
            flash('Username or BluegoldID already exists', 'danger')
        finally:
            conn.close()

        return redirect(url_for('faculty_update'))

    # GET
    return render_template('new_account.html')


@app.route('/student_edit', methods=['GET', 'POST'])
def student_edit():
    if 'user' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'student':
        flash('Students only page', 'danger')
        return redirect(url_for('index'))

    username = session['user']
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM students WHERE username = ?', (username,))
    student = c.fetchone()

    if request.method == 'POST':
        name = request.form.get('name')
        address = request.form.get('address')
        phone = request.form.get('phone')
        # Basic validation for phone when student updates their profile
        if phone and (not phone.isdigit() or len(phone) != 10):
            flash('Phone must be exactly 10 digits.', 'danger')
            conn.close()
            return redirect(url_for('student_edit'))
        # Students cannot modify GPA, credits, or balance
        c.execute('UPDATE students SET name = ?, address = ?, phone = ?, updated_at = ? WHERE username = ?',
                  (name, address, phone, datetime.utcnow().isoformat(), username))
        conn.commit()
        log_transaction(username, 'update_profile', 'Student updated personal info')
        flash('Profile updated', 'success')
        c.execute('SELECT * FROM students WHERE username = ?', (username,))
        student = c.fetchone()

    # load transactions related to this student
    c.execute('SELECT * FROM transactions WHERE actor_username = ? OR details LIKE ? ORDER BY timestamp DESC LIMIT 50',
              (username, f'%{username}%'))
    transactions = c.fetchall()
    conn.close()

    return render_template('student_edit.html', student=student, transactions=transactions)


@app.route('/faculty_update', methods=['GET', 'POST'])
def faculty_update():
    # Block non-faculty users. Students get redirected to index; unauthenticated users to login.
    if 'user' not in session:
        return redirect(url_for('login'))
    if session.get('role') == 'student' or session.get('role') != 'faculty':
        flash('Faculty only page', 'danger')
        return redirect(url_for('index'))

    conn = get_db_connection()
    c = conn.cursor()
    student = None
    transactions = []
    students = []

    if request.method == 'POST':
        action = request.form.get('action')
        target = request.form.get('target')
        student_id = request.form.get('student_id')
        # If a student_id is provided prefer it (hidden input in the form) to avoid ambiguous/empty target
        if student_id:
            try:
                sid = int(student_id)
                c.execute('SELECT * FROM students WHERE id = ?', (sid,))
            except Exception:
                c.execute('SELECT * FROM students WHERE username = ? OR bluegoldID = ?', (target, target))
        else:
            # target can be username or bluegoldID
            # find student by username or bluegoldID
            c.execute('SELECT * FROM students WHERE username = ? OR bluegoldID = ?', (target, target))
        student = c.fetchone()

        if action == 'search':
            if not student:
                flash('Student not found', 'warning')
            else:
                flash('Student found', 'success')
        elif action == 'update_academic' and student:
            gpa = request.form.get('gpa')
            credits = request.form.get('total_credits')
            # validate GPA and credits
            try:
                gpa_val = float(gpa) if gpa != '' and gpa is not None else 0.0
            except ValueError:
                flash('Invalid GPA value', 'danger')
                gpa_val = None
            try:
                credits_val = int(credits) if credits != '' and credits is not None else 0
            except ValueError:
                flash('Invalid credits value', 'danger')
                credits_val = None

            if gpa_val is None or credits_val is None:
                pass
            elif not (0.0 <= gpa_val <= 4.0):
                flash('GPA must be between 0.0 and 4.0', 'danger')
            elif credits_val < 0:
                flash('Credits must be non-negative', 'danger')
            else:
                c.execute('UPDATE students SET gpa = ?, total_credits = ?, updated_at = ? WHERE id = ?',
                          (gpa_val, credits_val, datetime.utcnow().isoformat(), student['id']))
                conn.commit()
                log_transaction(session['user'], 'update_academic', f'Updated {student["username"]} GPA={gpa_val} credits={credits_val}')
                flash('Academic record updated', 'success')
                c.execute('SELECT * FROM students WHERE id = ?', (student['id'],))
                student = c.fetchone()
        elif action == 'charge_tuition' and student:
            amount_raw = request.form.get('amount') or '0'
            try:
                amount = float(amount_raw)
            except ValueError:
                flash('Invalid amount', 'danger')
                amount = None

            if amount is not None:
                new_balance = (student['balance'] or 0.0) + amount
                c.execute('UPDATE students SET balance = ?, updated_at = ? WHERE id = ?',
                          (new_balance, datetime.utcnow().isoformat(), student['id']))
                conn.commit()
                log_transaction(session['user'], 'charge_tuition', f'Charged {amount} to {student["username"]}, balance now {new_balance}')
                flash(f'Charged ${amount:.2f} to {student["username"]}', 'success')
                c.execute('SELECT * FROM students WHERE id = ?', (student['id'],))
                student = c.fetchone()
        elif action == 'set_balance' and student:
            new_balance_raw = request.form.get('new_balance')
            try:
                new_balance = float(new_balance_raw)
                c.execute('UPDATE students SET balance = ?, updated_at = ? WHERE id = ?',
                          (new_balance, datetime.utcnow().isoformat(), student['id']))
                conn.commit()
                log_transaction(session['user'], 'set_balance', f'Set balance for {student["username"]} to {new_balance}')
                flash(f'Balance updated to ${new_balance:.2f}', 'success')
                c.execute('SELECT * FROM students WHERE id = ?', (student['id'],))
                student = c.fetchone()
            except (ValueError, TypeError):
                flash('Invalid balance value', 'danger')
        elif action == 'list':
            # show a list of students (handled below by querying all students)
            pass

    # load recent transactions
    c.execute('SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 100')
    transactions = c.fetchall()

    # if faculty wants to list students, or in general show a small roster, fetch students
    c.execute('SELECT * FROM students ORDER BY username LIMIT 200')
    students = c.fetchall()

    conn.close()

    return render_template('faculty_update.html', student=student, transactions=transactions, students=students)


@app.route('/transactions')
def transactions():
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 200')
    transactions = c.fetchall()
    conn.close()
    return render_template('transactions.html', transactions=transactions)


@app.before_request
def require_login_everywhere():
    # Allow unauthenticated access only to the login page and static files
    allowed_endpoints = ['login', 'static']
    # If the endpoint can't be determined (e.g., before first request), allow
    endpoint = None
    try:
        endpoint = request.endpoint
    except Exception:
        endpoint = None

    if endpoint in allowed_endpoints or endpoint is None:
        return

    if 'user' not in session:
        return redirect(url_for('login'))


create_database()


if __name__ == '__main__':
    # Simple CLI helper: python app.py --create-faculty username password
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == '--create-faculty':
        if len(sys.argv) < 4:
            print('Usage: python app.py --create-faculty <username> <password>')
            sys.exit(2)
        uname = sys.argv[2]
        pwd = sys.argv[3]
        ok = create_faculty_account(uname, pwd, actor='cli')
        if ok:
            print(f'Created faculty account: {uname}')
            sys.exit(0)
        else:
            print('Failed to create account: username may already exist')
            sys.exit(1)

    app.run(debug=True)


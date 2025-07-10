from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
import os
import secrets
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a random secret key
app.permanent_session_lifetime = timedelta(hours=24)  # Session expires after 24 hours

# Database setup
DATABASE = 'login.db'


def init_db():
    """Initialize the database with users table"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_user(student_email, password):
    """Create a new user with hashed password"""
    conn = get_db_connection()
    password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (student_email, password_hash) VALUES (?, ?)',
            (student_email, password_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Student Email already exists
    finally:
        conn.close()

def verify_user(student_email, password):
    """Verify user credentials"""
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE student_email = ?',
        (student_email,)
    ).fetchone()

    if user and check_password_hash(user['password_hash'], password):
        # Update last login
        conn.execute(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE student_email = ?',
            (student_email,)
        )
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False


@app.route('/')
def index():
    """Main page - redirect to login if not logged in"""
    if 'student_email' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        student_email = request.form.get('student_email', '').strip()
        password = request.form.get('password', '')

        if not student_email or not password:
            flash('Please enter both Student Email and Password', 'error')
            return render_template('login.html')

        if verify_user(student_email, password):
            session.permanent = True
            session['student_email'] = student_email
            flash(f'Welcome back, {student_email}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Student Email or Password', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""

    # ✅ Redirect if already logged in
    if 'student_email' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        student_email = request.form.get('student_email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not student_email or not password or not confirm_password:
            flash('Please fill in all fields', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        EMAIL_REGEX = r'^[\w\.-]+@aupp\.edu\.kh$'

        if not re.match(EMAIL_REGEX, student_email):
            flash('Email must be a valid AUPP student address ending with @aupp.edu.kh', 'error')
            return render_template('register.html')

        if create_user(student_email, password):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Student Email already exists. Please choose a different one.', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard - main app area (placeholder for now)"""
    if 'student_email' not in session:
        return redirect(url_for('login'))

    return render_template('dashboard.html', student_email=session['student_email'])

@app.route('/checkout')
def checkout():
    return render_template('checkout.html')

@app.route('/waiting')
def waiting():
    return render_template('waiting.html')


@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()

    print("🍽️  AUPP Eats Login System Starting...")
    print("📱 Visit: http://localhost:5000")
    print("🔐 Features: Secure login, registration, session management")
    print("💾 Database: SQLite with password hashing")
    print(f"💾 Database location: {DATABASE}")

    app.run(debug=True, host='0.0.0.0', port=5000)
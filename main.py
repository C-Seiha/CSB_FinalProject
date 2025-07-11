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

# Default admin credentials (you can modify these or create a separate admin setup)
DEFAULT_ADMIN_EMAIL = 'admin@aupp.edu.kh'
DEFAULT_ADMIN_PASSWORD = 'admin123'  # Change this in production!

def create_admin_account():
    """Create default admin account - run this once to set up admin"""
    conn = get_db_connection()
    
    # Check if admin already exists
    existing_admin = conn.execute(
        'SELECT * FROM admins WHERE admin_email = ?',
        (DEFAULT_ADMIN_EMAIL,)
    ).fetchone()
    
    if existing_admin:
        print(f"✅ Admin account already exists: {DEFAULT_ADMIN_EMAIL}")
        conn.close()
        return
    
    # Create new admin account
    password_hash = generate_password_hash(DEFAULT_ADMIN_PASSWORD, method='pbkdf2:sha256', salt_length=16)
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO admins (admin_email, password_hash) VALUES (?, ?)',
            (DEFAULT_ADMIN_EMAIL, password_hash)
        )
        conn.commit()
        print(f"✅ Admin account created successfully: {DEFAULT_ADMIN_EMAIL}")
        print(f"🔑 Admin Password: {DEFAULT_ADMIN_PASSWORD}")
        print("⚠️  IMPORTANT: Change this password after first login!")
    except sqlite3.IntegrityError:
        print(f"❌ Failed to create admin account - email already exists")
    finally:
        conn.close()

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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

    create_admin_account()


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

def verify_admin(admin_email, password):
    """Verify admin credentials"""
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT * FROM admins WHERE admin_email = ?',
        (admin_email,)
    ).fetchone()

    if admin and check_password_hash(admin['password_hash'], password):
        # Update last login
        conn.execute(
            'UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE admin_email = ?',
            (admin_email,)
        )
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False

@app.route('/')
def index():
    """Main page - redirect to appropriate dashboard if logged in"""
    if 'student_email' in session:
        return redirect(url_for('dashboard'))
    elif 'admin_email' in session:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - handles both user and admin login"""
    if request.method == 'POST':
        login_type = request.form.get('login_type', 'user')
        password = request.form.get('password', '')

        if not password:
            flash('Please enter your password', 'error')
            return render_template('login.html')

        if login_type == 'admin':
            admin_email = request.form.get('admin_email', '').strip()
            
            if not admin_email:
                flash('Please enter your admin email', 'error')
                return render_template('login.html')

            if verify_admin(admin_email, password):
                session.permanent = True
                session['admin_email'] = admin_email
                session['user_type'] = 'admin'
                flash(f'Welcome back, Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid Admin Email or Password', 'error')

        else:  # user login
            student_email = request.form.get('student_email', '').strip()
            
            if not student_email:
                flash('Please enter your student email', 'error')
                return render_template('login.html')

            if verify_user(student_email, password):
                session.permanent = True
                session['student_email'] = student_email
                session['user_type'] = 'user'
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

@app.route('/admin_dashboard')
def admin_dashboard():
    """Admin Dashboard - main admin area"""
    if 'admin_email' not in session:
        flash('Admin access required', 'error')
        return redirect(url_for('login'))

    return render_template('admin_dashboard.html', admin_email=session['admin_email'])

@app.route('/checkout')
def checkout():
    return render_template('checkout.html')

@app.route('/waiting')
def waiting():
    return render_template('waiting.html')


@app.route('/logout')
def logout():
    """Logout and clear session"""
    user_type = session.get('user_type', 'user')
    session.clear()
    
    if user_type == 'admin':
        flash('Admin logged out successfully', 'info')
    else:
        flash('You have been logged out successfully', 'info')
    
    return redirect(url_for('login'))




if __name__ == '__main__':
    init_db()

    print("🍽️  AUPP Eats Login System Starting...")
    print("📱 Visit: http://localhost:5000")
    print("🔐 Features: Secure login, registration, session management")
    print("👨‍💼 Admin Features: Admin login and dashboard")
    print("💾 Database: SQLite with password hashing")
    print(f"💾 Database location: {DATABASE}")
    print(f"🔑 Default Admin: {DEFAULT_ADMIN_EMAIL} / {DEFAULT_ADMIN_PASSWORD}")
    print("⚠️  IMPORTANT: Change default admin password in production!")

    app.run(debug=True, host='0.0.0.0', port=5000)

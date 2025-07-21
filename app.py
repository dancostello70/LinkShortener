from flask import Flask, request, redirect, render_template, flash, url_for, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Database configuration
DATABASE = config.DATABASE_NAME

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    
    # Create links table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shortcode TEXT UNIQUE NOT NULL,
            url TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create users table with new schema
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Migrate existing users table if needed
    try:
        # Check if is_admin column exists
        cursor = conn.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_admin' not in columns:
            # Add is_admin column to existing table
            conn.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0')
            # Set first user as admin (likely the original admin user)
            conn.execute('UPDATE users SET is_admin = 1 WHERE id = 1')
        
        if 'created_at' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            
        if 'last_login' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN last_login TIMESTAMP')
            
    except sqlite3.Error as e:
        print(f"Migration warning: {e}")
    
    # Create default admin user (username: admin, password: admin)
    # Change this in production!
    admin_hash = generate_password_hash(config.DEFAULT_ADMIN_PASSWORD)
    conn.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, is_admin) 
        VALUES (?, ?, ?)
    ''', (config.DEFAULT_ADMIN_USERNAME, admin_hash, 1))
    
    conn.commit()
    conn.close()

def login_required(f):
    """Decorator to require login for admin functions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin privileges required!', 'error')
            return redirect(url_for('admin'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            # Update last login timestamp
            conn.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', 
                (user['id'],)
            )
            conn.commit()
            conn.close()
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('Login successful!', 'success')
            return redirect(url_for('admin'))
        else:
            conn.close()
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/admin/logout')
def logout():
    """Logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    """Admin dashboard"""
    conn = get_db_connection()
    links = conn.execute(
        'SELECT * FROM links ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    
    return render_template('admin.html', links=links)

@app.route('/admin/add', methods=['POST'])
@login_required
def add_link():
    """Add new shortcode/URL pair"""
    shortcode = request.form['shortcode'].strip()
    url = request.form['url'].strip()
    
    if not shortcode or not url:
        flash('Both shortcode and URL are required!', 'error')
        return redirect(url_for('admin'))
    
    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO links (shortcode, url) VALUES (?, ?)',
            (shortcode, url)
        )
        conn.commit()
        flash(f'Shortcode "{shortcode}" added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash(f'Shortcode "{shortcode}" already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin'))

@app.route('/admin/edit/<int:link_id>', methods=['POST'])
@login_required
def edit_link(link_id):
    """Edit existing shortcode/URL pair"""
    shortcode = request.form['shortcode'].strip()
    url = request.form['url'].strip()
    
    if not shortcode or not url:
        flash('Both shortcode and URL are required!', 'error')
        return redirect(url_for('admin'))
    
    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE links SET shortcode = ?, url = ? WHERE id = ?',
            (shortcode, url, link_id)
        )
        conn.commit()
        flash(f'Link updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash(f'Shortcode "{shortcode}" already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin'))

@app.route('/admin/delete/<int:link_id>', methods=['POST'])
@login_required
def delete_link(link_id):
    """Delete shortcode/URL pair"""
    conn = get_db_connection()
    conn.execute('DELETE FROM links WHERE id = ?', (link_id,))
    conn.commit()
    conn.close()
    
    flash('Link deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/users')
@admin_required
def manage_users():
    """User management page (admin only)"""
    conn = get_db_connection()
    users = conn.execute(
        'SELECT * FROM users ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    
    return render_template('users.html', users=users)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_user():
    """Add new user (admin only)"""
    username = request.form['username'].strip()
    password = request.form['password'].strip()
    is_admin = 'is_admin' in request.form
    
    if not username or not password:
        flash('Username and password are required!', 'error')
        return redirect(url_for('manage_users'))
    
    if len(password) < 4:
        flash('Password must be at least 4 characters long!', 'error')
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    try:
        password_hash = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
            (username, password_hash, is_admin)
        )
        conn.commit()
        role = "admin" if is_admin else "user"
        flash(f'User "{username}" added successfully as {role}!', 'success')
    except sqlite3.IntegrityError:
        flash(f'Username "{username}" already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    """Edit user (admin only)"""
    username = request.form['username'].strip()
    is_admin = 'is_admin' in request.form
    password = request.form.get('password', '').strip()
    
    if not username:
        flash('Username is required!', 'error')
        return redirect(url_for('manage_users'))
    
    # Don't allow editing the current admin user's admin status
    if user_id == session['user_id'] and not is_admin:
        flash('You cannot remove your own admin privileges!', 'error')
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    try:
        if password:  # Only update password if provided
            if len(password) < 4:
                flash('Password must be at least 4 characters long!', 'error')
                return redirect(url_for('manage_users'))
            password_hash = generate_password_hash(password)
            conn.execute(
                'UPDATE users SET username = ?, is_admin = ?, password_hash = ? WHERE id = ?',
                (username, is_admin, password_hash, user_id)
            )
        else:
            conn.execute(
                'UPDATE users SET username = ?, is_admin = ? WHERE id = ?',
                (username, is_admin, user_id)
            )
        conn.commit()
        flash('User updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash(f'Username "{username}" already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete user (admin only)"""
    # Prevent deleting current user
    if user_id == session['user_id']:
        flash('You cannot delete your own account!', 'error')
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash(f'User "{user["username"]}" deleted successfully!', 'success')
    conn.close()
    
    return redirect(url_for('manage_users'))

@app.route('/admin/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html')

@app.route('/admin/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user's own password"""
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    if not current_password or not new_password or not confirm_password:
        flash('All fields are required!', 'error')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match!', 'error')
        return redirect(url_for('profile'))
    
    if len(new_password) < 4:
        flash('Password must be at least 4 characters long!', 'error')
        return redirect(url_for('profile'))
    
    conn = get_db_connection()
    user = conn.execute(
        'SELECT password_hash FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    
    if not user or not check_password_hash(user['password_hash'], current_password):
        flash('Current password is incorrect!', 'error')
        conn.close()
        return redirect(url_for('profile'))
    
    # Update password
    new_password_hash = generate_password_hash(new_password)
    conn.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (new_password_hash, session['user_id'])
    )
    conn.commit()
    conn.close()
    
    flash('Password changed successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/<path:shortcode>')
def redirect_link(shortcode):
    """Handle shortcode redirects"""
    conn = get_db_connection()
    link = conn.execute(
        'SELECT url FROM links WHERE shortcode = ?', (shortcode,)
    ).fetchone()
    conn.close()
    
    if link:
        return redirect(link['url'], code=302)
    else:
        return render_template('404.html', shortcode=shortcode), 404

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    # Run the app
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)

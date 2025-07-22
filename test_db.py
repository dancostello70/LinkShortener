import sqlite3
import sys
sys.path.append('.')
import config
from werkzeug.security import check_password_hash

# Test database connection and user verification
conn = sqlite3.connect(config.DATABASE_NAME)
conn.row_factory = sqlite3.Row

# Check if users table exists and has data
users = conn.execute('SELECT * FROM users').fetchall()
print("Users in database:")
for user in users:
    print(f"ID: {user['id']}, Username: {user['username']}")
    # Test password verification
    if check_password_hash(user['password_hash'], config.DEFAULT_ADMIN_PASSWORD):
        print(f"Password verification successful for {user['username']}")
    else:
        print(f"Password verification failed for {user['username']}")

# Check links table
links = conn.execute('SELECT * FROM links').fetchall()
print(f"\nLinks in database: {len(links)} total")
for link in links:
    print(f"Shortcode: {link['shortcode']}, URL: {link['url']}")

conn.close()

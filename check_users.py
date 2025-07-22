import sqlite3

conn = sqlite3.connect('links.db')
conn.row_factory = sqlite3.Row

users = conn.execute('SELECT username, is_admin FROM users').fetchall()
print('Current users:')
for user in users:
    admin_status = "Yes" if user['is_admin'] else "No"
    print(f'Username: {user["username"]}, Is Admin: {admin_status}')

conn.close()

import sqlite3

conn = sqlite3.connect('login.db')
cursor = conn.cursor()

# Query all users
cursor.execute("SELECT * FROM users")
users = cursor.fetchall()

# Print results
for user in users:
    print(user)

conn.close()
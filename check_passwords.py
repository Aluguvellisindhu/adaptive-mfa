import sqlite3
conn = sqlite3.connect("mfa_system.db")
cur = conn.cursor()
cur.execute("SELECT username,password_hash FROM users")
rows = cur.fetchall()
for row in rows:
    print(row)
conn.close()


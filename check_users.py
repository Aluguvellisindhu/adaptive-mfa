import sqlite3
conn = sqlite3.connect("mfa_system.db")
cur = conn.cursor()

cur.execute("SELECT username FROM users")
print(cur.fetchall())

conn.close()
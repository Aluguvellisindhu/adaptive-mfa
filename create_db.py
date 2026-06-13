cur.execute("""
INSERT OR IGNORE INTO users (username,email, password)
VALUES ('admin', 'admin@gmail.com, 'admin123')
""")

cur.execute("""
INSERT OR IGNORE INTO users (username,email,password)
VALUES ('testuser', 'test@gmail.com','test123')
""")

conn.commit()
conn.close()

print("Database created successfully")
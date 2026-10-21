import sqlite3

connection = sqlite3.connect("vulnlab.db")

connection.execute("""
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUENOT NULL,
    password_hash TEXT NOT NULL
    )
""")

connection.commit()
connection.close()

print("Database and users table are ready!")

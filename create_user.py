import sqlite3
import hashlib
import secrets

username = "alice"
password = "demo123"

salt = secrets.token_bytes(16)

password_hash = hashlib.scrypt(
    password.encode(),
    salt = salt,
    n = 2**14,
    r = 8,
    p = 1
)

stored_hash = salt.hex() + ":" + password_hash.hex()

connection = sqlite3.connect("vulnlab.db")

connection.execute(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    (username, stored_hash)
)

connection.commit()
connection.close()

print("Test user created succesfully!")
import sqlite3
import hashlib
import secrets

from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return "vulnlab is my cybersecurity learning project."

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    connection = sqlite3.connect("vulnlab.db")

    row = connection.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    connection.close()

    if row is None:
        return "Invalid username or password.", 401
    
    salt_hex, saved_hash_hex = row[0]. split(":")

    salt = bytes.fromhex(salt_hex)
    saved_hash = bytes.fromhex(saved_hash_hex)

    submitted_hash = hashlib.scrypt(
        password.encode(),
        salt = salt,
        n = 2**14,
        r = 8,
        p = 1
    )

    if secrets.compare_digest(submitted_hash, saved_hash):
        return "Demo Login successful!"

    return "Invalid username or password.", 401



if __name__ == "__main__":
    app.run(debug=True)
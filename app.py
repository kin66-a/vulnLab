import sqlite3
import hashlib
import secrets

from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return "vulnlab is my cybersecurity learning project."

@app.route("/register", methods = ["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    
    username = request.form.get("username","").strip()
    password = request.form.get("Password","")

    if not username or not password:
        return "Username and password are required.", 400

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

    try:
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, stored_hash)
        )
        connection.commit()
    except sqlite3.IntegrityError:
        return "Username already exists.", 409
    finally:
        connection.close()
    
    return "Registration successful!"

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
        session["username"] = username
        return "Demo Login successful!"

    return "Invalid username or password.", 401

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return "please log in first.", 401

    return f"Welcome to your dashboard, {session['username']} !"

if __name__ == "__main__":
    app.run(debug=True)
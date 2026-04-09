from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os

app = Flask(__name__)

# In-memory user store
users = {}

# ---------------- SIGNUP ----------------
@app.route("/api/signup", methods=["POST"])
def signup():
    if not request.is_json:
        return jsonify({"error": "Invalid request"}), 400

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if username in users:
        return jsonify({"error": "User already exists"}), 409

    hashed_password = generate_password_hash(password)

    users[username] = {
        "password": hashed_password
    }

    return jsonify({"message": "User registered successfully"}), 201


# ---------------- LOGIN ----------------
@app.route("/api/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"error": "Invalid request"}), 400

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username not in users:
        return jsonify({"error": "Invalid username or password"}), 401

    stored_password = users[username]["password"]

    if not check_password_hash(stored_password, password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Generate simple session token
    token = str(uuid.uuid4())

    return jsonify({
        "message": "Login successful",
        "token": token
    })


# ---------------- HOME ----------------
@app.route("/")
def home():
    return "Signup & Login API is running"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

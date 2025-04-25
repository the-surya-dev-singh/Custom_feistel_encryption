import socket
import sqlite3
import os
import hashlib
import time
from flask import Flask, render_template, request, redirect, url_for, flash, session
from collections import defaultdict

# Dictionary to track login attempts per IP address for rate limiting
login_attempts = defaultdict(list)

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for sessions and security

# -----------------------------
# Custom Feistel Encryption Algorithm
# -----------------------------
def feistel_encrypt(data, key='securekey'):
    rounds = 4  # Number of encryption rounds
    left, right = data[:len(data)//2], data[len(data)//2:]
    for i in range(rounds):
        temp = right
        # XOR operation for encryption round
        right = ''.join(chr(ord(l) ^ ord(k)) for l, k in zip(left, key[:len(left)]))
        left = temp
    return left + right  # Combine the halves for encrypted output

# -----------------------------
# Custom Feistel Decryption Algorithm
# -----------------------------
def feistel_decrypt(data, key='securekey'):
    rounds = 4
    left, right = data[:len(data)//2], data[len(data)//2:]
    for i in range(rounds):
        temp = left
        # XOR operation to reverse the encryption round
        left = ''.join(chr(ord(r) ^ ord(k)) for r, k in zip(right, key[:len(right)]))
        right = temp
    return left + right  # Combine the halves for decrypted output

# -----------------------------
# Custom HMAC-like Hashing Function
# -----------------------------
def custom_hmac(message, secret_key='hmac_key'):
    block_size = 64  # Block size for HMAC
    if len(secret_key) > block_size:
        secret_key = hashlib.sha256(secret_key.encode()).hexdigest()
    secret_key = secret_key.ljust(block_size, '0')  # Pad key to block size

    # Outer and inner pad creation
    o_key_pad = ''.join(chr(ord(x) ^ 0x5C) for x in secret_key)
    i_key_pad = ''.join(chr(ord(x) ^ 0x36) for x in secret_key)

    # Hashing process
    inner_hash = hashlib.sha256((i_key_pad + message).encode()).hexdigest()
    return hashlib.sha256((o_key_pad + inner_hash).encode()).hexdigest()

# -----------------------------
# Set up the SQLite database
# -----------------------------
def setup_database():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    # Create table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

# -----------------------------
# Store user credentials securely
# -----------------------------
def store_credentials(username, password):
    encrypted_password = feistel_encrypt(password)  # Encrypt the password
    hmac_signature = custom_hmac(encrypted_password)  # Generate HMAC of encrypted password
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    # Store username and HMAC signature in database
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hmac_signature))
    conn.commit()
    conn.close()

# -----------------------------
# Verify user credentials on login
# -----------------------------
def verify_credentials(username, password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    conn.close()
    # Encrypt input password to compare HMAC
    decrypted_password = feistel_encrypt(password)  # This simulates consistent transformation
    if result and result[0] == custom_hmac(decrypted_password):
        return True
    return False

# -----------------------------
# Home route
# -----------------------------
@app.route('/')
def index():
    return render_template('index.html')  # Render login/register page

# -----------------------------
# Registration handler
# -----------------------------
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    store_credentials(username, password)  # Save user to database
    flash('User registered successfully.')
    return redirect(url_for('index'))

# -----------------------------
# Login handler with rate limiting
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip = request.remote_addr  # Get client IP address
    now = time.time()

    # Remove outdated login attempts (>60 seconds ago)
    login_attempts[ip] = [ts for ts in login_attempts[ip] if now - ts < 60]
    current_attempt = len(login_attempts[ip]) + 1  # Attempt number the user is on
    # Check if the IP has exceeded allowed attempts
    if len(login_attempts[ip]) >= 5:
        flash('Too many login attempts. Please wait and try again.')
        return redirect(url_for('index'))

    # Record current attempt
    login_attempts[ip].append(now)

    # Validate credentials
    if verify_credentials(username, password):
        session['username'] = username  # Set session on success
        login_attempts[ip] = []  # Reset attempts
        flash('Login successful!')
        return redirect(url_for('success'))
    else:
        flash(f'Invalid credentials! Attempt {current_attempt} of 5.')  # Show attempt count
        return redirect(url_for('index'))

# -----------------------------
# Success route (post-login)
# -----------------------------
@app.route('/success')
def success():
    return render_template('success.html')  # Render success page after login

# -----------------------------
# App entry point
# -----------------------------
if __name__ == '__main__':
    setup_database()  # Ensure DB is ready
    app.run(debug=True)  # Run the Flask app in debug mode

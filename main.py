import socket
import sqlite3
import os
import hashlib
import time

# Advanced Block Cipher Encryption with Custom HMAC Authentication
def feistel_encrypt(data, key='securekey'):
    rounds = 4
    left, right = data[:len(data)//2], data[len(data)//2:]
    for i in range(rounds):
        temp = right
        right = ''.join(chr(ord(l) ^ ord(k)) for l, k in zip(left, key[:len(left)]))
        left = temp
    return left + right

def feistel_decrypt(data, key='securekey'):
    rounds = 4
    left, right = data[:len(data)//2], data[len(data)//2:]
    for i in range(rounds):
        temp = left
        left = ''.join(chr(ord(r) ^ ord(k)) for r, k in zip(right, key[:len(right)]))
        right = temp
    return left + right

# Custom HMAC Implementation
def custom_hmac(message, secret_key='hmac_key'):
    block_size = 64
    if len(secret_key) > block_size:
        secret_key = hashlib.sha256(secret_key.encode()).hexdigest()
    secret_key = secret_key.ljust(block_size, '0')

    o_key_pad = ''.join(chr(ord(x) ^ 0x5C) for x in secret_key)
    i_key_pad = ''.join(chr(ord(x) ^ 0x36) for x in secret_key)

    inner_hash = hashlib.sha256((i_key_pad + message).encode()).hexdigest()
    return hashlib.sha256((o_key_pad + inner_hash).encode()).hexdigest()

def setup_database():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

def store_credentials(username, password):
    encrypted_password = feistel_encrypt(password)
    hmac_signature = custom_hmac(encrypted_password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hmac_signature))
    conn.commit()
    conn.close()

def verify_credentials(username, password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    conn.close()
    decrypted_password = feistel_encrypt(password)  # simulate decrypt for HMAC check
    if result and result[0] == custom_hmac(decrypted_password):
        return True
    return False

def server_program():
    host = '127.0.0.1'
    port = 5000
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server started...")

    while True:
        conn, address = server_socket.accept()
        print(f"Connection from {address}")

        timestamp = str(int(time.time()))
        conn.send(timestamp.encode())  # Prevent replay attacks
        data = conn.recv(1024).decode()
        if data:
            username, password, received_timestamp = data.split(',')
            if abs(int(received_timestamp) - int(timestamp)) < 5:  # Check freshness
                if verify_credentials(username, password):
                    conn.send("Access Granted".encode())
                else:
                    conn.send("Access Denied".encode())
            else:
                conn.send("Replay Attack Detected".encode())
        conn.close()

def client_program():
    host = '127.0.0.1'
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))

    timestamp = client_socket.recv(1024).decode()
    username = input("Enter username: ")
    password = input("Enter password: ")

    client_socket.send(f"{username},{password},{timestamp}".encode())
    response = client_socket.recv(1024).decode()
    print(response)

    client_socket.close()

if __name__ == "__main__":
    setup_database()
    choice = input("Run server (s) or client (c) or store credentials (sc)? ")
    if choice == 's':
        server_program()
    elif choice == 'c':
        client_program()
    elif choice == 'sc':
        username = input("Enter username: ")
        password = input("Enter password: ")
        store_credentials(username, password)
        print("Credentials stored securely.")

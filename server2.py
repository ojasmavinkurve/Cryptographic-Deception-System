import socket
import threading
import time
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Signature import pkcs1_15
from collections import defaultdict
from Crypto.Util.Padding import pad
import random
from Crypto.Hash import HMAC
import csv
from joblib import load

REAL_DATA_DIR = "data/real"
FAKE_DATA_DIR = "data/fake"

model = load("model/isolation_forest.pkl")
scaler = load("model/scaler.pkl")

connection_log = []

HOST = 'localhost'
PORT = 65432

users = {
    'alice': {
        'password_hash': SHA256.new(b'alicepassword').digest(),
        'aes_key': SHA256.new(b'alicepassword').digest()[:32]
    },
    'admin': {
        'password_hash': SHA256.new(b'secureadminpass').digest(),
        'aes_key': SHA256.new(b'secureadminpass').digest()[:32]
    }
}

bruteforce_tracking = defaultdict(dict)
failed_attempts = defaultdict(list)
ATTEMPT_THRESHOLD = 3
TIME_WINDOW = 60

server_key = RSA.generate(2048)
server_public_key = server_key.publickey()

def handle_client(conn, addr):
    ip = addr[0]
    print(f"Connected by {addr}")
    is_fake_session = False
    fake_aes_key = None

    
    session_info = {
        'ip': ip,
        'username': "",
        'start_time': time.time(),
        'file_requests': [],
        'intervals': [],
    }


    try:
        conn.sendall(server_public_key.export_key())
        client_pub_key = RSA.import_key(conn.recv(4096))

        encrypted_digest = conn.recv(256)
        signature = conn.recv(4096)

        auth_digest = PKCS1_OAEP.new(server_key).decrypt(encrypted_digest)
        pkcs1_15.new(client_pub_key).verify(SHA256.new(auth_digest), signature)

        username, password_hash = auth_digest[:5].decode(), auth_digest[5:]
        session_info['username']= username
        valid_credentials = username in users and password_hash == users[username]['password_hash']

        
        now = time.time()
        current_attempts = [t for t in failed_attempts[ip] if now - t <= TIME_WINDOW]

        if valid_credentials:
            conn.sendall(b"AUTH_SUCCESS")
            print(f"Authenticated: {username}")
        else:
            print(f"Failed login from {ip}")
            failed_attempts[ip].append(now)
            current_attempts = [t for t in failed_attempts[ip] if now - t <= TIME_WINDOW]
            failed_attempts[ip] = current_attempts

            if ip in bruteforce_tracking:
                bruteforce_tracking[ip]['post_attempts'] += 1
                if bruteforce_tracking[ip]['post_attempts'] >= bruteforce_tracking[ip]['n']:
                    conn.sendall(b"AUTH_SUCCESS")
                    is_fake_session = True
                    fake_aes_key = password_hash[:32]
                    print(f"Deceiving attacker from {ip}")
                else:
                    conn.sendall(b"AUTH_FAIL")
            else:
                if len(current_attempts) >= ATTEMPT_THRESHOLD:
                    bruteforce_tracking[ip] = {
                        'n': random.randint(1, 5),
                        'post_attempts': 0
                    }
                    failed_attempts[ip].clear()
                    print(f"Brute-force detected from {ip}, n={bruteforce_tracking[ip]['n']}")
                    conn.sendall(b"AUTH_FAIL")
                else:
                    conn.sendall(b"AUTH_FAIL")

        while True:
            filename = conn.recv(1024).decode().strip().lower()


            now = time.time()
            if session_info['file_requests']:
                delta = now - session_info['file_requests'][-1]['timestamp']
                session_info['intervals'].append(delta)
            session_info['file_requests'].append({'filename': filename, 'timestamp': now})

            if filename == 'quit':
                break

            if is_fake_session:
                decoy_file = os.path.join(FAKE_DATA_DIR, f"fake_{filename}")
                if os.path.exists(decoy_file):
                    with open(decoy_file, 'rb') as f:
                        fake_content = pad(f.read(), AES.block_size)
                        iv = Random.new().read(AES.block_size)
                        cipher = AES.new(fake_aes_key, AES.MODE_CBC, iv)
                        encrypted = iv + cipher.encrypt(fake_content)
                        conn.sendall(encrypted + b"FILE_END")

                    print(f"Sent decoy file '{decoy_file}' to {ip}")

                else:
                    conn.sendall(b"FILE_NOT_FOUND_FILE_END")
                    print(f"Decoy file '{decoy_file}' not found")
            else:
                real_file = os.path.join(REAL_DATA_DIR, filename)
                if not is_fake_session:
                    if os.path.exists(real_file):
                        with open(real_file, 'rb') as f:
                            data = pad(f.read(), AES.block_size)
                            iv = Random.new().read(AES.block_size)
                            cipher = AES.new(users[username]['aes_key'], AES.MODE_CBC, iv)
                            encrypted = iv + cipher.encrypt(data)
                            conn.sendall(encrypted + b"FILE_END")
                    else:
                        conn.sendall(b"FILE_NOT_FOUND_FILE_END")
                else:
                    decoy_file = os.path.join(FAKE_DATA_DIR, f"fake_{filename}")
                    if os.path.exists(decoy_file):
                        with open(decoy_file, 'rb') as f:
                            fake_content = pad(f.read(), AES.block_size)
                            iv = Random.new().read(AES.block_size)
                            cipher = AES.new(fake_aes_key, AES.MODE_CBC, iv)
                            encrypted = iv + cipher.encrypt(fake_content)
                            conn.sendall(encrypted + b"FILE_END")
                        print(f"Sent decoy file '{decoy_file}' to {ip}")
                    else:
                        conn.sendall(b"FILE_NOT_FOUND_FILE_END")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if is_fake_session:
            del bruteforce_tracking[ip]
            failed_attempts[ip].clear()
        conn.close()

    if session_info['file_requests']:
        total_requests = len(session_info['file_requests'])
        avg_interval = sum(session_info['intervals']) / len(session_info['intervals']) if session_info['intervals'] else 0
        filenames = [req['filename'] for req in session_info['file_requests']]
        entropy = sum([len(set(fname)) for fname in filenames]) / total_requests 

        sample = scaler.transform([[total_requests, avg_interval, entropy]])
        prediction = model.predict(sample)[0]
        predicted_fake = 1 if prediction == -1 else 0

        if not is_fake_session and predicted_fake:
            print(f"[ML WARNING] Session from {ip} flagged as fake by model.")
            is_fake_session = 1 

        connection_log.append({
            'ip': session_info['ip'],
            'username': session_info['username'],
            'num_requests': total_requests,
            'avg_interval': round(avg_interval, 3),
            'filename_entropy': round(entropy, 3),
            'is_fake_session': int(is_fake_session),
        })

        os.makedirs("logs", exist_ok=True)
        with open("logs/connection_log.csv", "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=connection_log[-1].keys())
            if f.tell() == 0:
                writer.writeheader()
            writer.writerow(connection_log[-1])



def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()

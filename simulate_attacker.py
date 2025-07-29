import socket
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

HOST = 'localhost'
PORT = 65432

def simulate_attack():
    attacker_key = RSA.generate(2048)
    attacker_pub = attacker_key.publickey()

    for i in range(3):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                server_pub_key = RSA.import_key(s.recv(4096))
                s.sendall(attacker_pub.export_key())

                username = "admin"
                password = f"wrong{i}"
                password_hash = SHA256.new(password.encode()).digest()
                auth_data = username.encode() + password_hash

                encrypted_auth = PKCS1_OAEP.new(server_pub_key).encrypt(auth_data)
                s.sendall(encrypted_auth)

                signature = pkcs1_15.new(attacker_key).sign(SHA256.new(auth_data))
                s.sendall(signature)

                result = s.recv(1024)
                print(f"[Auth Attempt {i+1}] Server says: {result}")
        except Exception as e:
            print(f"[Error on attempt {i+1}]: {e}")
        time.sleep(0.5)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            server_pub_key = RSA.import_key(s.recv(4096))
            s.sendall(attacker_pub.export_key())

            username = "admin"
            password = "stillwrong"
            password_hash = SHA256.new(password.encode()).digest()
            auth_data = username.encode() + password_hash

            encrypted_auth = PKCS1_OAEP.new(server_pub_key).encrypt(auth_data)
            s.sendall(encrypted_auth)

            signature = pkcs1_15.new(attacker_key).sign(SHA256.new(auth_data))
            s.sendall(signature)

            result = s.recv(1024)
            print(f"[4th Attempt] Server says: {result}")

            for i in range(3):
                fname = "company_data.txt"
                s.sendall(fname.encode())
                print(f"[Attacker] Requested file: {fname}")
                data = b""
                buffer = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                if b"FILE_END" in buffer:
                    data, _ = buffer.split(b"FILE_END", 1)
                    break
            print(f"[Attacker] Received (truncated): {data[:100]}...\n")
            time.sleep(0.3)

            s.sendall(b"quit")
    except Exception as e:
        print(f"[Attacker] Final error: {e}")

if __name__ == "__main__":
    simulate_attack()

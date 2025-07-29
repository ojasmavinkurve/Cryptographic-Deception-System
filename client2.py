import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC


HOST = 'localhost'
PORT = 65432

def derive_aes_key(password):
    return SHA256.new(password.encode()).digest()[:32]

def receive_file(conn):
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:  
            break
        data += chunk
        if data.endswith(b"FILE_END"):
            data = data[:-8]
            break
    return data

def main():
    client_key = RSA.generate(2048)
    client_public_key = client_key.publickey()
    username = input("Enter username: ")
    password = input("Enter password: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")

            server_pub_key = RSA.import_key(s.recv(4096))
            s.sendall(client_public_key.export_key())

            password_hash = SHA256.new(password.encode()).digest()
            auth_data = username.encode() + password_hash
            encrypted_auth = PKCS1_OAEP.new(server_pub_key).encrypt(auth_data)
            s.sendall(encrypted_auth)

            signature = pkcs1_15.new(client_key).sign(SHA256.new(auth_data))
            s.sendall(signature)

            auth_result = s.recv(1024)
            if auth_result == b"AUTH_SUCCESS":
                print("\nAuthentication successful!")
                while True:
                    filename = input("\nEnter filename to request (or 'quit'): ").strip()
                    if filename.lower() == 'quit':
                        s.sendall(b'quit')
                        break
                    
                    s.sendall(filename.encode())
                    encrypted_file = receive_file(s)
                    
                    if encrypted_file == b"FILE_NOT_FOUND":
                        print(f"\n[Server]: The file '{filename}' was not found.")
                        continue
                        
                    try:
                        aes_key = derive_aes_key(password)
                        iv = encrypted_file[:AES.block_size]
                        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                        decrypted = unpad(cipher.decrypt(encrypted_file[AES.block_size:]), AES.block_size)
                        print(f"\n[Received Content]\n{decrypted.decode()}")
                    except Exception as e:
                        print(f"Decryption error: {str(e)}")
            else:
                print("Authentication failed. Invalid credentials.")

        except Exception as e:
            print(f"Connection error: {str(e)}")
        finally:
            s.close()
            print("Connection closed.")

if __name__ == "__main__":
    main()

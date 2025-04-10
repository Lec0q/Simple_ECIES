import time
import csv
from ecies.utils import generate_eth_key
from ecies import decrypt as ecc_decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import socket
import json

# File log hiệu suất
PERFORMANCE_LOG_FILE = "performance_log.csv"

# Hàm ghi log hiệu suất vào file CSV
def log_performance(step, duration):
    with open(PERFORMANCE_LOG_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([step, f"{duration:.15f}"])
    print(f"[Performance] {step}: {duration:.15f} seconds")

# --------- Chức năng tạo khóa ECC ---------
def ecc_priv_key_gen():
    print("[Server] Generating ECC private key...")
    start = time.time()
    priv_key = generate_eth_key()
    end = time.time()
    log_performance("ECC private key generation", end - start)
    print("[Server] ECC Private Key (hex):")
    print(priv_key.to_hex())
    return priv_key

def ecc_pub_key_gen(ecc_priv_key):
    print("[Server] Deriving ECC public key from the private key...")
    start = time.time()
    pub_key = ecc_priv_key.public_key.to_hex()
    end = time.time()
    log_performance("ECC public key derivation", end - start)
    print("[Server] ECC Public Key (hex):")
    print(pub_key)
    return pub_key

# --------- Chức năng giải mã AES CBC ---------
def aes_cbc_decrypt(aes_cipher_text, aes_key):
    print("[Server] Extracting IV from AES ciphertext...")
    iv = aes_cipher_text[:16]
    print("[Server] Extracted IV (hex):", iv.hex())
    print("[Server] Decrypting ciphertext (excluding IV)...")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    start = time.time()
    plaintext_padded = cipher.decrypt(aes_cipher_text[16:])
    plaintext = unpad(plaintext_padded, AES.block_size)
    end = time.time()
    log_performance("AES-CBC decryption", end - start)
    return plaintext

# --------- Thiết lập máy chủ TCP ---------
HOST = '0.0.0.0'
PORT = 65432

# Ghi header cho file CSV (chỉ ghi nếu file chưa tồn tại)
with open(PERFORMANCE_LOG_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Step", "Duration (seconds)"])

print("=== Server: Step 1 - ECC Key Generation ===")
ecc_priv = ecc_priv_key_gen()
ecc_pub = ecc_pub_key_gen(ecc_priv)

print("\n=== Server: Step 2 - Starting TCP Server ===")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Server] Listening on {HOST}:{PORT} ...")
    
    conn, addr = s.accept()
    with conn:
        print(f"\n[Server] Step 3 - Connection established with {addr}")
        
        print("[Server] Step 4 - Sending ECC public key to client...")
        conn.sendall(ecc_pub.encode())
        
        print("\n[Server] Step 5 - Waiting to receive encrypted file data from client...")
        data = b""
        while True:
            packet = conn.recv(4096)
            if not packet:
                break
            data += packet
            try:
                json.loads(data.decode())
                break
            except json.JSONDecodeError:
                continue

        if not data:
            print("[Server] Error: No data received from client.")
        else:
            received = json.loads(data.decode())
            encrypted_aes_key_hex = received["encrypted_aes_key"]
            encrypted_file_hex = received["encrypted_file"]
            print("[Server] Received encrypted data from client:")
            print("  Encrypted AES Key (hex):", encrypted_aes_key_hex)
            print("  Encrypted File Data (hex):", encrypted_file_hex)

            encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
            encrypted_file = bytes.fromhex(encrypted_file_hex)
            print("[Server] Converted AES key and file data from hex to bytes.")

            # Lưu file mã hóa ra đĩa
            encrypted_filename = "encrypted_file_copy.bin"
            with open(encrypted_filename, "wb") as f_enc:
                f_enc.write(encrypted_file)
            print(f"[Server] Encrypted file copy saved as '{encrypted_filename}'.")

            print("\n[Server] Step 6 - Decrypting AES key using ECC private key...")
            start = time.time()
            aes_key = ecc_decrypt(ecc_priv.to_hex(), encrypted_aes_key)
            end = time.time()
            log_performance("ECC decryption of AES key", end - start)
            print("[Server] Decrypted AES Key (hex):", aes_key.hex())

            print("\n[Server] Step 7 - Decrypting AES-CBC encrypted file data...")
            file_data = aes_cbc_decrypt(encrypted_file, aes_key)
            
            output_filename = "received_file.txt"
            with open(output_filename, "wb") as f_out:
                f_out.write(file_data)
            print(f"\n[Server] Step 8 - Decryption complete. Decrypted file saved as '{output_filename}'.")

import time
import csv
import json
import socket
import binascii
from ecies import encrypt as ecc_encrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# --------- Performance log file configuration ---------
PERFORMANCE_LOG_FILE = "client_performance_log.csv"

# Function to write performance log into CSV file
def log_performance(step, duration):
    with open(PERFORMANCE_LOG_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([step, f"{duration:.15f}"])
    print(f"[Performance] {step}: {duration:.15f} seconds")

# Write CSV header (only if the file doesn't exist)
with open(PERFORMANCE_LOG_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Step", "Duration (seconds)"])

# --------- AES CBC encryption function ---------
def aes_cbc_encrypt(plaintext, aes_key):
    print("[Client] Generating random 16-byte IV for AES encryption...")
    iv = get_random_bytes(16)
    print("[Client] Generated IV (hex):", iv.hex())
    print("[Client] Padding file data and encrypting using AES CBC mode...")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Return IV concatenated with ciphertext (used for decryption)
    return iv + ciphertext

# --------- Setup TCP client ---------
HOST = '127.0.0.1'  # Change to server IP if running on a different machine
PORT = 65432

# Step 0: Read the file to be sent (in binary mode)
input_filename = "file_to_send.txt"
print(f"=== Client: Reading file '{input_filename}' to send ===")
start = time.time()
with open(input_filename, "rb") as f:
    file_data = f.read()
end = time.time()
log_performance("File read", end - start)
print(f"[Client] Read {len(file_data)} bytes from '{input_filename}'.")

# Step 1: Connect to server
print("\n=== Client: Step 1 - Connecting to Server ===")
start = time.time()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    end = time.time()
    log_performance("TCP connection", end - start)
    print(f"[Client] Connected to server at {HOST}:{PORT}")

    # Step 2: Receive ECC public key from server
    print("\n[Client] Step 2 - Receiving ECC public key from server...")
    start = time.time()
    ecc_pub = s.recv(4096).decode()
    end = time.time()
    log_performance("Receive ECC public key", end - start)
    print("[Client] Received ECC Public Key (hex):")
    print(ecc_pub)

    # Step 3: Generate random AES key (16 bytes)
    print("\n[Client] Step 3 - Generating random AES key (16 bytes)...")
    start = time.time()
    aes_key = get_random_bytes(16)
    end = time.time()
    log_performance("AES key generation", end - start)
    print("[Client] Generated AES Key (hex):", aes_key.hex())

    # Step 4: Encrypt AES key using the server's ECC public key (ECIES)
    print("\n[Client] Step 4 - Encrypting AES key using server's ECC public key...")
    start = time.time()
    encrypted_aes_key = ecc_encrypt(ecc_pub, aes_key)
    end = time.time()
    log_performance("ECC encryption of AES key", end - start)
    print("[Client] Encrypted AES Key (hex):", binascii.hexlify(encrypted_aes_key).decode())

    # Step 5: Encrypt file data using AES CBC mode with the generated AES key
    print("\n[Client] Step 5 - Encrypting file data using AES CBC mode...")
    start = time.time()
    encrypted_file = aes_cbc_encrypt(file_data, aes_key)
    end = time.time()
    log_performance("AES-CBC encryption", end - start)
    print("[Client] Encrypted File Data (IV + ciphertext, hex):", binascii.hexlify(encrypted_file).decode())

    # Step 6: Package encrypted AES key and encrypted file data into JSON (hex encoded)
    print("\n[Client] Step 6 - Packaging encrypted data into JSON format...")
    start = time.time()
    data = {
        "encrypted_aes_key": binascii.hexlify(encrypted_aes_key).decode(),
        "encrypted_file": binascii.hexlify(encrypted_file).decode()
    }
    json_data = json.dumps(data)
    end = time.time()
    log_performance("JSON packaging", end - start)
    print("[Client] JSON Data to send:", data)

    # Step 7: Send JSON data to the server via TCP connection
    print("\n[Client] Step 7 - Sending encrypted data to the server...")
    start = time.time()
    s.sendall(json_data.encode())
    end = time.time()
    log_performance("Sending data", end - start)
    print("[Client] Encrypted data sent successfully.")

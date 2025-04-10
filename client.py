import time
import csv
import json
import socket
import binascii
from ecies import encrypt as ecc_encrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# --------- Cấu hình file log hiệu suất ---------
PERFORMANCE_LOG_FILE = "client_performance_log.csv"

# Hàm ghi log hiệu suất vào file CSV
def log_performance(step, duration):
    with open(PERFORMANCE_LOG_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([step, f"{duration:.15f}"])
    print(f"[Performance] {step}: {duration:.15f} seconds")

# Ghi header cho file CSV (chỉ ghi nếu file chưa tồn tại)
with open(PERFORMANCE_LOG_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Step", "Duration (seconds)"])

# --------- Hàm mã hóa AES CBC ---------
def aes_cbc_encrypt(plaintext, aes_key):
    print("[Client] Generating random 16-byte IV for AES encryption...")
    iv = get_random_bytes(16)
    print("[Client] Generated IV (hex):", iv.hex())
    print("[Client] Padding file data and encrypting using AES CBC mode...")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Trả về IV nối với ciphertext (để sử dụng cho giải mã)
    return iv + ciphertext

# --------- Thiết lập máy khách TCP ---------
HOST = '127.0.0.1'  # Thay đổi thành IP của server nếu chạy trên máy khác
PORT = 65432

# Bước 0: Đọc tệp cần chuyển (ở chế độ nhị phân)
input_filename = "file_to_send.txt"
print(f"=== Client: Reading file '{input_filename}' to send ===")
start = time.time()
with open(input_filename, "rb") as f:
    file_data = f.read()
end = time.time()
log_performance("File read", end - start)
print(f"[Client] Read {len(file_data)} bytes from '{input_filename}'.")

# Bước 1: Kết nối tới server
print("\n=== Client: Step 1 - Connecting to Server ===")
start = time.time()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    end = time.time()
    log_performance("TCP connection", end - start)
    print(f"[Client] Connected to server at {HOST}:{PORT}")

    # Bước 2: Nhận khóa công khai ECC từ server
    print("\n[Client] Step 2 - Receiving ECC public key from server...")
    start = time.time()
    ecc_pub = s.recv(4096).decode()
    end = time.time()
    log_performance("Receive ECC public key", end - start)
    print("[Client] Received ECC Public Key (hex):")
    print(ecc_pub)

    # Bước 3: Tạo khóa AES ngẫu nhiên (16 byte)
    print("\n[Client] Step 3 - Generating random AES key (16 bytes)...")
    start = time.time()
    aes_key = get_random_bytes(16)
    end = time.time()
    log_performance("AES key generation", end - start)
    print("[Client] Generated AES Key (hex):", aes_key.hex())

    # Bước 4: Mã hóa khóa AES bằng cách sử dụng khóa công khai ECC của server (ECIES)
    print("\n[Client] Step 4 - Encrypting AES key using server's ECC public key...")
    start = time.time()
    encrypted_aes_key = ecc_encrypt(ecc_pub, aes_key)
    end = time.time()
    log_performance("ECC encryption of AES key", end - start)
    print("[Client] Encrypted AES Key (hex):", binascii.hexlify(encrypted_aes_key).decode())

    # Bước 5: Mã hóa dữ liệu tệp sử dụng AES ở chế độ CBC với khóa AES đã tạo
    print("\n[Client] Step 5 - Encrypting file data using AES CBC mode...")
    start = time.time()
    encrypted_file = aes_cbc_encrypt(file_data, aes_key)
    end = time.time()
    log_performance("AES-CBC encryption", end - start)
    print("[Client] Encrypted File Data (IV + ciphertext, hex):", binascii.hexlify(encrypted_file).decode())

    # Bước 6: Đóng gói khóa AES đã mã hóa và dữ liệu tệp đã mã hóa thành JSON (đã mã hóa hex)
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

    # Bước 7: Gửi dữ liệu JSON đến server qua kết nối TCP
    print("\n[Client] Step 7 - Sending encrypted data to the server...")
    start = time.time()
    s.sendall(json_data.encode())
    end = time.time()
    log_performance("Sending data", end - start)
    print("[Client] Encrypted data sent successfully.")

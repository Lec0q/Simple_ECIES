# Simple_ECIES
Below is a sample README.md file you can use for your GitHub repository. It explains the purpose of the project, details the client–server implementation for secure file transfer, lists the required dependencies, and provides instructions on setup and usage.

---

```markdown
# Secure File Transfer with ECC and AES Encryption

This project demonstrates a secure file transfer system using a combination of symmetric and asymmetric encryption. The client encrypts a file using AES in CBC mode and then encrypts the AES key using ECC (Elliptic Curve Cryptography) via ECIES. The server, upon receiving the encrypted data via a TCP socket, decrypts the AES key using its ECC private key and then decrypts the file content.

## Overview

This project comprises two Python scripts:

- client.py: 
  - Reads a file (default: `file_to_send.txt`).
  - Generates a random AES key and encrypts the file using AES in CBC mode.
  - Encrypts the AES key using the server's ECC public key (using ECIES).
  - Packages the encrypted AES key and file into a JSON object.
  - Sends the JSON data to the server over a TCP socket.

- server.py: 
  - Generates an ECC key pair (public and private keys).
  - Listens for incoming TCP connections.
  - Sends its ECC public key to the client.
  - Receives the encrypted JSON data.
  - Decrypts the AES key using its ECC private key.
  - Decrypts the file using AES decryption.
  - Saves the received file as `received_file.txt`.

## Features

- AES-CBC Encryption**: Secures file data with a random 16-byte initialization vector.
- ECC Encryption via ECIES**: Ensures secure key transmission between the client and server.
- TCP Socket Communication**: Enables real-time data transfer.
- Performance Logging**: Measures and logs the execution time of each encryption, decryption, and communication step in CSV format.

## Dependencies

The project requires the following Python packages:

- [ecies](https://pypi.org/project/ecies/) (for ECC encryption/decryption)
- [pycryptodome](https://pycryptodome.readthedocs.io/) (for AES encryption and decryption)
- Standard libraries: `socket`, `time`, `csv`, `json`, `binascii`

```

_Note: Make sure to use the correct package names. Some systems might require additional configuration for installing `pycryptodome`._

## Project Structure

```
.
├── client.py              # Client code for encrypting and sending file data
├── server.py              # Server code for receiving and decrypting file data
├── file_to_send.txt       # Example file to be transferred (provide your own file)
├── performance_log.csv    # Log file for server performance metrics
└── client_performance_log.csv  # Log file for client performance metrics
```

## Setup and Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/secure-file-transfer.git
   cd secure-file-transfer
   ```

2. **Install Dependencies:**

   Run the following command to install the necessary libraries:

   ```bash
   pip install eciespy pycryptodome
   ```

3. **Prepare the File for Transfer:**

   Place the file you wish to send in the same directory as `client.py` and name it `file_to_send.txt` or update the filename in the client script accordingly.

## Usage

1. **Run the Server:**

   Start the server first so it is ready to accept connections.

   ```bash
   python server.py
   ```

   The server will:
   - Generate an ECC key pair.
   - Listen for TCP connections on port `65432`.
   - Send its ECC public key upon establishing a connection.

2. **Run the Client:**

   Open another terminal window and run the client.

   ```bash
   python client.py
   ```

   The client will:
   - Read the file (`file_to_send.txt`).
   - Encrypt the file and AES key.
   - Connect to the server at `127.0.0.1` on port `65432`.
   - Transmit the JSON packaged encrypted data to the server.

3. **Result:**

   The server will decrypt the received file data and save it as `received_file.txt`. Performance metrics will be logged in the respective CSV log files.

## Performance Logging

Both the client and the server log the duration of each major step:
- Client: Logs for file reading, TCP connection, ECC encryption of AES key, AES-CBC encryption, and JSON packaging.
- Server: Logs for ECC key generation, AES-CBC decryption, and the overall decryption process.

These logs are saved in:
- `client_performance_log.csv` (client-side)
- `performance_log.csv` (server-side)

Review these files to analyze and improve the performance of each operation.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


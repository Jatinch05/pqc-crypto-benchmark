# 🛡️ PQC vs Traditional Cryptography: Benchmarking Patient Data Encryption

This project compares **traditional cryptography (AES-GCM + HMAC)** with **post-quantum cryptography (Kyber + AES-CTR + Dilithium)** for securely storing and retrieving patient details in a MySQL database. It measures CPU usage, memory usage, and time taken for encryption and decryption.

---

## 🚀 Features

- 🔐 Encrypts patient data using:
  - **Traditional:** AES-GCM
  - **PQC:** ML-KEM (Kyber512) + AES-CTR + ML-DSA (Dilithium44)
- ✅ Verifies data integrity using:
  - **Traditional:** AES-GCM
  - **PQC:** Digital signature with Dilithium
- 📊 Benchmarks:
  - Time taken
  - CPU usage
  - RAM usage
- 💾 Stores encrypted data in **MySQL database**
- 🌐 Simple Flask-based web interface

---

## 🧪 Cryptography Stack

| Feature       | Traditional       | PQC (Post-Quantum)          |
|---------------|-------------------|-----------------------------|
| Encryption    | AES-GCM           | AES-CTR                     |
| Key Exchange  | Random AES Key    | Kyber (ML-KEM)              |
| Integrity     | AES-GCM           | Dilithium (ML-DSA)          |
| Quantum Safe? | ❌ No             | ✅ Yes                       |

---

# 🛠️ Setup Instructions

## 1. Clone the repository

```bash
git clone https://github.com/your-username/pqc-crypto-benchmark.git
cd pqc-crypto-benchmark
# Linux / macOS
python3.10 -m venv venv
source venv/bin/activate
```
## 2. Create & activate a Python virtual environment
### Windows (PowerShell)
```bash
python3.10 -m venv venv
.\venv\Scripts\Activate.ps1
```
### Linux / macOS
```bash
python3.10 -m venv venv
source venv/bin/activate
```
## 3. Install Dependencies
```bash
pip install -r requirements.txt
```
## 4. Configure MySQL
### Start your MySQL server.
### Log in and run:
```bash
CREATE DATABASE pqc_demo;
USE pqc_demo;

CREATE TABLE patient_data (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name TEXT,
  age TEXT,
  condition TEXT,
  ciphertext BLOB,
  tag BLOB,
  iv_or_nonce BLOB,
  kyber_ct BLOB,
  signature BLOB,
  scheme VARCHAR(20)
);

```
### Open database.py and update the DB_CONFIG dictionary:
```bash
DB_CONFIG = {
    "host": "localhost",
    "user": "your_mysql_user",
    "password": "your_mysql_password",
    "database": "pqc_demo"
}

```
## 5. Run the app
### python app.py

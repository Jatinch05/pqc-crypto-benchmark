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
| Integrity     | HMAC              | Dilithium (ML-DSA)          |
| Quantum Safe? | ❌ No              | ✅ Yes                       |

---

## 🛠️ Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/your-username/pqc-crypto-benchmark.git
cd pqc-crypto-benchmark

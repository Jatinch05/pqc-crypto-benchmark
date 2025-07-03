import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.ml_dsa import ML_DSA_44

class TraditionalCrypto:
    def __init__(self):
        self.key = os.urandom(32)

    def encrypt(self, data: str) -> tuple:
        start_time = time.perf_counter()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data.encode()) + encryptor.finalize()
        tag = encryptor.tag
        aes_time = (time.perf_counter() - start_time) * 1000
        print(f"Traditional AES-GCM Encryption Time: {aes_time:.2f} ms, Data Size: {len(data.encode())} bytes")
        return ct, tag, iv, self.key, {'aes_gcm': aes_time}

    def decrypt(self, ct: bytes, tag: bytes, iv: bytes, key: bytes) -> tuple:
        start_time = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            pt_bytes = decryptor.update(ct) + decryptor.finalize()
            aes_time = (time.perf_counter() - start_time) * 1000
            print(f"Traditional AES-GCM Decryption Time: {aes_time:.2f} ms")
            return pt_bytes.decode(), {'aes_gcm': aes_time}
        except:
            return None, None

class PQCCrypto:
    def __init__(self):
        self.pk_kyber, self.sk_kyber = ML_KEM_512.keygen()
        self.pk_dilithium, self.sk_dilithium = ML_DSA_44.keygen()

    def encrypt(self, data: str) -> tuple:
        data_size = len(data.encode())
        # Kyber encapsulation
        start_time = time.perf_counter()
        shared_key, kyber_ct = ML_KEM_512.encaps(self.pk_kyber)
        kyber_time = (time.perf_counter() - start_time) * 1000

        # AES-CTR encryption (replacing AES-GCM)
        start_time = time.perf_counter()
        aes_key = shared_key[:32]
        nonce = os.urandom(16)  # Nonce for AES-CTR (same length as IV)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data.encode()) + encryptor.finalize()
        aes_time = (time.perf_counter() - start_time) * 1000

        # Dilithium signing
        start_time = time.perf_counter()
        msg_to_sign = ct + kyber_ct  # No tag since we're using AES-CTR
        sig = ML_DSA_44.sign(self.sk_dilithium, msg_to_sign)
        dilithium_time = (time.perf_counter() - start_time) * 1000

        total_time = kyber_time + aes_time + dilithium_time
        print(f"PQC Kyber Encapsulation Time: {kyber_time:.2f} ms")
        print(f"PQC AES-CTR Encryption Time: {aes_time:.2f} ms")
        print(f"PQC Dilithium Signing Time: {dilithium_time:.2f} ms")
        print(f"PQC Total Encryption Time: {total_time:.2f} ms, Data Size: {data_size} bytes")
        timings = {'kyber': kyber_time, 'aes_ctr': aes_time, 'dilithium': dilithium_time}
        return ct, None, nonce, kyber_ct, sig, self.sk_kyber, self.pk_dilithium, timings

    def decrypt(self, ct: bytes, tag: bytes, nonce: bytes, kyber_ct: bytes, sig: bytes, sk_kyber: bytes, pk_dilithium: bytes) -> tuple:
        start_time = time.perf_counter()
        msg_to_verify = ct + kyber_ct  # No tag to include
        if not ML_DSA_44.verify(pk_dilithium, msg_to_verify, sig):
            return None, None
        dilithium_time = (time.perf_counter() - start_time) * 1000

        start_time = time.perf_counter()
        shared_key = ML_KEM_512.decaps(sk_kyber, kyber_ct)
        kyber_time = (time.perf_counter() - start_time) * 1000

        start_time = time.perf_counter()
        aes_key = shared_key[:32]
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            pt_bytes = decryptor.update(ct) + decryptor.finalize()
            aes_time = (time.perf_counter() - start_time) * 1000
            total_time = dilithium_time + kyber_time + aes_time
            print(f"PQC Dilithium Verification Time: {dilithium_time:.2f} ms")
            print(f"PQC Kyber Decapsulation Time: {kyber_time:.2f} ms")
            print(f"PQC AES-CTR Decryption Time: {aes_time:.2f} ms")
            print(f"PQC Total Decryption Time: {total_time:.2f} ms")
            timings = {'kyber': kyber_time, 'aes_ctr': aes_time, 'dilithium': dilithium_time}
            return pt_bytes.decode(), timings
        except:
            return None, None
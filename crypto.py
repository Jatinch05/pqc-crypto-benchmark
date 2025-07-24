import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.ml_dsa import ML_DSA_44

from Crypto.PublicKey   import RSA
from Crypto.Cipher      import PKCS1_OAEP, AES
from Crypto.Signature   import pss
from Crypto.Hash        import SHA256
from Crypto.Random      import get_random_bytes


class TraditionalCrypto:
    def __init__(self):
        self._rsa_key = RSA.generate(2048)
        self._rsa_pub = self._rsa_key.publickey()

    def encrypt(self, data: str) -> tuple:
        t0 = time.perf_counter()
        aes_key = get_random_bytes(32)
        kem_ct = PKCS1_OAEP.new(self._rsa_pub).encrypt(aes_key)
        t1 = time.perf_counter()

        iv = get_random_bytes(8)
        aes = AES.new(aes_key, AES.MODE_CTR, nonce=iv)
        ct = aes.encrypt(data.encode())
        t2 = time.perf_counter()

        h = SHA256.new(ct + kem_ct)
        signature = pss.new(self._rsa_key).sign(h)
        t3 = time.perf_counter()

        timings = {
            'rsa_kem_ms': (t1 - t0) * 1000,
            'aes_ctr_ms': (t2 - t1) * 1000,
            'rsa_pss_ms': (t3 - t2) * 1000,
        }
        print(f"Traditional Total Encryption Time: {sum(timings.values()):.2f} ms")

        return ct, None, iv, aes_key, timings, kem_ct, signature

    def decrypt(self, ciphertext, signature, iv, kem_ct, aes_key) -> tuple:
        print("=== Traditional Decrypt ===")
        print("Ciphertext:", ciphertext)
        print("Signature:", signature)
        print("IV:", iv)
        print("KEM CT:", kem_ct)
        print("AES Key:", aes_key.hex())

        try:
            t0 = time.perf_counter()

            # Verify RSA-PSS
            h = SHA256.new(ciphertext + kem_ct)
            pss.new(self._rsa_pub).verify(h, signature)
            t1 = time.perf_counter()

            # Decapsulate RSA-OAEP
            actual_key = PKCS1_OAEP.new(self._rsa_key).decrypt(kem_ct)
            t2 = time.perf_counter()

            # Decrypt AES-CTR
            aes = AES.new(actual_key, AES.MODE_CTR, nonce=iv)
            pt = aes.decrypt(ciphertext).decode()
            t3 = time.perf_counter()

            timings = {
                'rsa_pss_ver_ms': (t1 - t0) * 1000,
                'rsa_kem_dec_ms': (t2 - t1) * 1000,
                'aes_ctr_dec_ms': (t3 - t2) * 1000,
            }
            print(f"Traditional Total Decryption Time: {sum(timings.values()):.2f} ms")

            return pt, timings
        except Exception as e:
            print("Decryption failed:", str(e))
            return None, {}


class PQCCrypto:
    def __init__(self):
        self._kyber      = ML_KEM_512
        self.pk_kyber, self.sk_kyber = self._kyber.keygen()
        self._dilithium = ML_DSA_44
        self.pk_dilithium, self.sk_dilithium = self._dilithium.keygen()

    def encrypt(self, data: str) -> tuple:
        t0 = time.perf_counter()
        shared, kyber_ct = self._kyber.encaps(self.pk_kyber)
        t1 = time.perf_counter()

        aes_key = shared[:32]
        nonce   = os.urandom(16)
        cipher  = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
        ct       = cipher.encryptor().update(data.encode()) + cipher.encryptor().finalize()
        t2       = time.perf_counter()

        sig      = self._dilithium.sign(self.sk_dilithium, ct + kyber_ct)
        t3       = time.perf_counter()

        timings = {
            'kyber_ms':     (t1 - t0) * 1000,
            'aes_ctr_ms':   (t2 - t1) * 1000,
            'dilithium_ms': (t3 - t2) * 1000,
        }
        print(f"PQC Total Encryption Time: {sum(timings.values()):.2f} ms")

        return ct, None, nonce, kyber_ct, sig, self.sk_kyber, self.pk_dilithium, timings

    def decrypt(self, ct, tag, nonce, kyber_ct, sig, sk, pk) -> tuple:
        t0 = time.perf_counter()
        if not self._dilithium.verify(pk, ct + kyber_ct, sig):
            return None, None
        t1 = time.perf_counter()

        shared = self._kyber.decaps(sk, kyber_ct)
        t2     = time.perf_counter()

        cipher   = Cipher(algorithms.AES(shared[:32]), modes.CTR(nonce), backend=default_backend())
        pt_bytes = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        t3       = time.perf_counter()

        timings = {
            'dilithium_ms': (t1 - t0) * 1000,
            'kyber_ms':     (t2 - t1) * 1000,
            'aes_ctr_ms':   (t3 - t2) * 1000,
        }
        print(f"PQC Total Decryption Time: {sum(timings.values()):.2f} ms")

        return pt_bytes.decode(), timings

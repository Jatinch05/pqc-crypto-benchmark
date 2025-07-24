import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.ml_dsa import ML_DSA_44

# PyCryptodome imports for RSA KEM & PSS
from Crypto.PublicKey   import RSA
from Crypto.Cipher      import PKCS1_OAEP, AES
from Crypto.Signature   import pss
from Crypto.Hash        import SHA256
from Crypto.Random      import get_random_bytes


class TraditionalCrypto:
    def __init__(self):
        # Server RSA keypair (2048-bit)
        self._rsa_key = RSA.generate(2048)
        self._rsa_pub = self._rsa_key.publickey()

    def encrypt(self, data: str) -> tuple:
        # Phase 1 — RSA‑OAEP encapsulation
        t0 = time.perf_counter()
        aes_key = get_random_bytes(32)
        kem_ct  = PKCS1_OAEP.new(self._rsa_pub).encrypt(aes_key)
        t1 = time.perf_counter()

        # Phase 2 — AES‑CTR encrypt
        iv   = get_random_bytes(8)  # 8-byte nonce for PyCryptodome
        aes  = AES.new(aes_key, AES.MODE_CTR, nonce=iv)
        ct   = aes.encrypt(data.encode())
        t2   = time.perf_counter()

        # Phase 3 — RSA‑PSS signing
        msg       = ct + kem_ct
        h         = SHA256.new(msg)
        signature = pss.new(self._rsa_key).sign(h)
        t3        = time.perf_counter()

        timings = {
            'rsa_kem_ms':   (t1 - t0) * 1000,
            'aes_ctr_ms':   (t2 - t1) * 1000,
            'rsa_pss_ms':   (t3 - t2) * 1000,
        }
        print(f"Traditional Total Encryption Time: {sum(timings.values()):.2f} ms")

        # returns: ct, placeholder tag, iv, display_key, per-phase timings, kem_ct, signature
        return ct, None, iv, aes_key, timings, kem_ct, signature

    def decrypt(self, ct: bytes, tag: bytes, iv: bytes, key: bytes) -> tuple:
        # Here `tag` holds the signature, and `key` holds the KEM ciphertext
        signature = tag
        kem_ct    = key

        # Phase 1 — verify RSA‑PSS
        t0 = time.perf_counter()
        h  = SHA256.new(ct + kem_ct)
        try:
            pss.new(self._rsa_pub).verify(h, signature)
        except (ValueError, TypeError):
            return None, None
        t1 = time.perf_counter()

        # Phase 2 — RSA‑OAEP decapsulation
        aes_key = PKCS1_OAEP.new(self._rsa_key).decrypt(kem_ct)
        t2      = time.perf_counter()

        # Phase 3 — AES‑CTR decrypt
        aes     = AES.new(aes_key, AES.MODE_CTR, nonce=iv)
        pt      = aes.decrypt(ct).decode()
        t3      = time.perf_counter()

        timings = {
            'rsa_pss_ver_ms': (t1 - t0) * 1000,
            'rsa_kem_dec_ms': (t2 - t1) * 1000,
            'aes_ctr_dec_ms': (t3 - t2) * 1000,
        }
        print(f"Traditional Total Decryption Time: {sum(timings.values()):.2f} ms")

        return pt, timings


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

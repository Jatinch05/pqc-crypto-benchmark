import os
from dotenv import load_dotenv
import mysql.connector

# Load .env for local dev
load_dotenv()

class Database:
    def __init__(self):
        self.conn = mysql.connector.connect(
            host     = os.getenv("DB_HOST", "localhost"),
            user     = os.getenv("DB_USER", "root"),
            password = os.getenv("DB_PASSWORD", ""),
            database = os.getenv("DB_NAME", "benchmark"),
            port     = int(os.getenv("DB_PORT", 3306))
        )
        self.cursor = self.conn.cursor()

    def insert_patient(self, method, ct, tag, iv, kyber_ct=None, sig=None):
        """
        Inserts an encrypted patient record into the database.
        For traditional: ct, tag=signature, iv, kyber_ct=RSA-KEM CT, sig=None
        For PQC:         ct, tag=None,      iv, kyber_ct=Kyber CT,  sig=Dilithium sig
        """
        query = """
        INSERT INTO patient_data 
            (method, encrypted_data, tag, iv, kyber_ct, sig)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        self.cursor.execute(query, (method, ct, tag, iv, kyber_ct, sig))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_patient(self, id):
        """
        Returns: method, encrypted_data, tag, iv, kyber_ct, sig
        """
        query = """
        SELECT method, encrypted_data, tag, iv, kyber_ct, sig 
        FROM patient_data 
        WHERE id = %s
        """
        self.cursor.execute(query, (id,))
        return self.cursor.fetchone()

    def reset_table(self):
        self.cursor.execute("TRUNCATE TABLE patient_data")
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()

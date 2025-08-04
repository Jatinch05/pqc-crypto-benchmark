import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

class Database:
    def __init__(self):
        dsn = (
            f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
            f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
            "?sslmode=require"
        )
        self.conn = psycopg.connect(dsn)
        self.cursor = self.conn.cursor()

    def insert_patient(self, method, ct, tag, iv, kyber_ct=None, sig=None):
        query = """
        INSERT INTO patient_data 
            (method, encrypted_data, tag, iv, kyber_ct, sig)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """
        self.cursor.execute(query, (method, ct, tag, iv, kyber_ct, sig))
        self.conn.commit()
        return self.cursor.fetchone()[0]

    def get_patient(self, id):
        query = """
        SELECT method, encrypted_data, tag, iv, kyber_ct, sig 
        FROM patient_data 
        WHERE id = %s
        """
        self.cursor.execute(query, (id,))
        return self.cursor.fetchone()

    def reset_table(self):
        self.cursor.execute("TRUNCATE TABLE patient_data RESTART IDENTITY;")
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()

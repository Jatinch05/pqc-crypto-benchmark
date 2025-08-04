import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

class Database:
    def __init__(self):
        # Build DSN and connect
        dsn = (
            f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
            f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
            "?sslmode=require"
        )
        self.conn = psycopg.connect(dsn, autocommit=False)
        self.cursor = self.conn.cursor()

        # Auto-create table if missing
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS patient_data (
                id           SERIAL      PRIMARY KEY,
                method       TEXT        NOT NULL,
                encrypted_data BYTEA     NOT NULL,
                tag          BYTEA,
                iv           BYTEA       NOT NULL,
                kyber_ct     BYTEA,
                sig          BYTEA
            );
        """)
        self.conn.commit()

    def insert_patient(self, method, ct, tag, iv, kyber_ct=None, sig=None):
        """
        Inserts an encrypted patient record into the database.
        Positional only—no keywords—to avoid signature mismatches.
        """
        query = """
        INSERT INTO patient_data 
            (method, encrypted_data, tag, iv, kyber_ct, sig)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id;
        """
        try:
            self.cursor.execute(query, (method, ct, tag, iv, kyber_ct, sig))
            new_id = self.cursor.fetchone()[0]
            self.conn.commit()
            return new_id
        except Exception:
            # Roll back the failed transaction so next one can proceed
            self.conn.rollback()
            raise

    def get_patient(self, id):
        query = """
        SELECT method, encrypted_data, tag, iv, kyber_ct, sig
        FROM patient_data
        WHERE id = %s;
        """
        self.cursor.execute(query, (id,))
        return self.cursor.fetchone()

    def reset_table(self):
        try:
            self.cursor.execute("TRUNCATE TABLE patient_data RESTART IDENTITY;")
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def close(self):
        self.cursor.close()
        self.conn.close()

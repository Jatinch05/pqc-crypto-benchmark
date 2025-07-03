from flask import Flask, request, render_template
from crypto import TraditionalCrypto, PQCCrypto
from database import Database
from benchmark import Benchmark

app = Flask(__name__)

db = Database()
traditional_crypto = TraditionalCrypto()
pqc_crypto = PQCCrypto()

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    benchmark_data = {'traditional': None, 'pqc': None}
    crypto_timings = {'traditional': None, 'pqc': None}
    action_type = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'encrypt':
            action_type = 'encrypt'
            name = request.form['name']
            age = request.form['age']
            condition = request.form['condition']
            patient_details = f"Name: {name}, Age: {age}, Condition: {condition}"

            # Traditional Encryption
            benchmark_traditional = Benchmark()
            benchmark_traditional.start()
            trad_ct, trad_tag, trad_iv, trad_key, trad_timings = traditional_crypto.encrypt(patient_details)
            benchmark_data['traditional'] = benchmark_traditional.stop()
            crypto_timings['traditional'] = trad_timings
            trad_id = db.insert_patient('traditional', trad_ct, trad_tag, trad_iv)

            # PQC Encryption
            benchmark_pqc = Benchmark()
            benchmark_pqc.start()
            pqc_ct, _, pqc_nonce, pqc_kyber_ct, pqc_sig, pqc_sk_kyber, pqc_pk_dilithium, pqc_timings = pqc_crypto.encrypt(patient_details)
            benchmark_data['pqc'] = benchmark_pqc.stop()
            crypto_timings['pqc'] = pqc_timings
            pqc_id = db.insert_patient('pqc', pqc_ct, None, pqc_nonce, kyber_ct=pqc_kyber_ct, sig=pqc_sig)

            result = (f"Traditional Data stored with ID: {trad_id}<br>"
                      f"Key: {trad_key.hex()}<br><br>"
                      f"PQC Data stored with ID: {pqc_id}<br>"
                      f"Kyber Secret Key: {pqc_sk_kyber.hex()}<br>"
                      f"Dilithium Public Key: {pqc_pk_dilithium.hex()}")

        elif action == 'decrypt':
            action_type = 'decrypt'
            id_ = int(request.form['id'])
            method = request.form['decrypt_method']
            data = db.get_patient(id_)
            if not data:
                result = "Patient not found"
                return render_template('index.html', result=result, benchmark_data=benchmark_data, crypto_timings=crypto_timings, action_type=action_type)

            encrypted_data = data[2]
            tag = data[3]
            iv_or_nonce = data[4]  # IV for Traditional, nonce for PQC
            kyber_ct = data[5]
            sig = data[6]

            benchmark = Benchmark()
            benchmark.start()
            if method == 'traditional':
                key = bytes.fromhex(request.form['traditional_key'])
                pt, timings = traditional_crypto.decrypt(encrypted_data, tag, iv_or_nonce, key)
                benchmark_data['traditional'] = benchmark.stop()
                crypto_timings['traditional'] = timings
                benchmark_data['pqc'] = None
                crypto_timings['pqc'] = None
            elif method == 'pqc':
                sk_kyber = bytes.fromhex(request.form['kyber_sk'])
                pk_dilithium = bytes.fromhex(request.form['dilithium_pk'])
                pt, timings = pqc_crypto.decrypt(encrypted_data, tag, iv_or_nonce, kyber_ct, sig, sk_kyber, pk_dilithium)
                benchmark_data['pqc'] = benchmark.stop()
                crypto_timings['pqc'] = timings
                benchmark_data['traditional'] = None
                crypto_timings['traditional'] = None
            else:
                result = "Invalid method"
                return render_template('index.html', result=result, benchmark_data=benchmark_data, crypto_timings=crypto_timings, action_type=action_type)

            if pt is None:
                result = "Decryption failed"
            else:
                result = f"Decrypted data: {pt}"

        elif action == 'reset':
            action_type = 'reset'
            db.reset_table()
            result = "Table reset successfully. IDs will start from 1."

    return render_template('index.html', result=result, benchmark_data=benchmark_data, crypto_timings=crypto_timings, action_type=action_type)

if __name__ == '__main__':
    app.run(debug=True)
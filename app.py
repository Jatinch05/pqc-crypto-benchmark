from flask import Flask, request, render_template
from crypto    import TraditionalCrypto, PQCCrypto
from database  import Database
from benchmark import Benchmark

app = Flask(__name__)
db  = Database()
trad = TraditionalCrypto()
pqc  = PQCCrypto()

@app.route('/', methods=['GET','POST'])
def index():
    result = None
    benchmark_data = {'traditional': None, 'pqc': None}
    crypto_timings = {'traditional': None,'pqc': None}
    action_type = None

    if request.method == 'POST':
        action = request.form['action']

        if action == 'encrypt':
            action_type = 'encrypt'
            pd = f"Name: {request.form['name']}, Age: {request.form['age']}, Condition: {request.form['condition']}"

            # Traditional Encryption
            b1 = Benchmark(); b1.start()
            t_ct, _, t_iv, t_key, t_times, t_kem, t_sig = trad.encrypt(pd)
            benchmark_data['traditional'] = b1.stop()
            crypto_timings['traditional'] = t_times
            trad_id = db.insert_patient('traditional', t_ct, t_sig, t_iv, kyber_ct=t_kem, sig=t_sig)

            # PQC Encryption
            b2 = Benchmark(); b2.start()
            p_ct, _, p_iv, p_kem, p_sig, p_sk, p_pk, p_times = pqc.encrypt(pd)
            benchmark_data['pqc'] = b2.stop()
            crypto_timings['pqc'] = p_times
            pqc_id = db.insert_patient('pqc', p_ct, None, p_iv, kyber_ct=p_kem, sig=p_sig)

            result = (
                f"Traditional ID: {trad_id}, AES Key: {t_key.hex()}<br>"
                f"PQC ID: {pqc_id}, Kyber SK: {p_sk.hex()}, Dilithium PK: {p_pk.hex()}"
            )

        elif action == 'decrypt':
            action_type = 'decrypt'
            rec = db.get_patient(int(request.form['id']))
            if not rec:
                result = "Patient not found"
            else:
                _, _, ct, tag, iv, kem_ct, sig = rec
                b = Benchmark(); b.start()
                if request.form['decrypt_method'] == 'traditional':
                    pt, dt = trad.decrypt(ct, tag, iv, kem_ct)
                    benchmark_data['traditional'] = b.stop()
                    crypto_timings['traditional'] = dt
                else:
                    sk = bytes.fromhex(request.form['kyber_sk'])
                    pk = bytes.fromhex(request.form['dilithium_pk'])
                    pt, dt = pqc.decrypt(ct, tag, iv, kem_ct, sig, sk, pk)
                    benchmark_data['pqc'] = b.stop()
                    crypto_timings['pqc'] = dt
                result = f"Decrypted: {pt}" if pt else "Decryption failed."

        else:
            action_type = 'reset'
            db.reset_table()
            result = "Table reset successfully."

    return render_template('index.html',
        result=result,
        benchmark_data=benchmark_data,
        crypto_timings=crypto_timings,
        action_type=action_type
    )

if __name__ == '__main__':
    app.run(debug=True)

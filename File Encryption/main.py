#libraries
import base64
import hashlib
from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog
import subprocess
import mysql.connector

#database connection
#con = mysql.connector.connect(host="localhost", user="root", password="", database="EFile")

#createcursor object
#cursor = con.cursor()

#variables
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

#generate key
key = Fernet.generate_key()
print(key)
with open('cache/key', 'wb') as filekey:
   filekey.write(key)

#current hardware id
current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
print(current_machine_id)

#functions
def encrypt(raw, key):
    private_key = hashlib.sha256(key).digest()
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key=private_key, mode=AES.MODE_CFB, iv=iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def decrypt(enc, key):
    private_key = hashlib.sha256(key).digest()
    unpad = lambda s: s[:-ord(s[-1:])]
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(private_key, AES.MODE_CFB, iv)
    return unpad(base64.b64decode(cipher.decrypt(enc[AES.block_size:])).decode('utf8'))

def regdev():
    current_machine_id = str(subprocess.check_output('wmic bios get serialnumber'), 'utf-8').split('\n')[1].strip()

#file select
root = tk.Tk()
root.withdraw()
file = filedialog.askopenfilename()
file = open(file, "rb")
raw = str(file.read())

#encrypt
encrypted = encrypt(raw, key)
print(encrypted)
file.close()

#write encrypted file
file = open('cache/enc', "wb")
file.write(encrypted)
file.close()

#decrypt
decrypted = decrypt(encrypted, key)
print(decrypted)
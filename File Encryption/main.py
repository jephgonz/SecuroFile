#LIBRARIES
import base64
import hashlib
from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog
import subprocess
import mysql.connector
import zipfile
from pathlib import Path

#DB CONNECTION
con = mysql.connector.connect(host="localhost", user="root", password="", database="capstone")

#DB CURSOR
cursor = con.cursor()
query = "select * from user_devices"
cursor.execute(query)
table = cursor.fetchall()
for row in table:
    print(row[0])
    print(row[1])
    print(row[2])
    print(row[3])
    print(row[4])

#VARIABLES
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
list_files = ['cache/header', 'cache/key', 'cache/enc']
key = 'null'
user_id = 'null'

#GET HARDWARE UUID
current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
print(current_machine_id)

#FUNCTIONS
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

def writeenc(encrypted):
    file = open('cache/enc', "wb")
    file.write(encrypted)
    file.close()

def compressenc(file_name):
    with zipfile.ZipFile('encrypted/' + file_name + '', 'w') as zipF:
        for file in list_files:
            zipF.write(file, compress_type=zipfile.ZIP_DEFLATED)

def extractenc(file_name):
    with zipfile.ZipFile('encrypted/' + file_name + '', 'r') as zip_ref:
        zip_ref.extractall('')

def genkey():
    key = Fernet.generate_key()
    print(key)
    with open('cache/key', 'wb') as filekey:
        filekey.write(key)

def regdev():
    devId = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
    cursor.execute("INSERT INTO `devices`(`dev_id`, `user_id`, `deviceID`, `date_registered`, `date_modified`) "
                   "VALUES ('',"+user_id+","+devId+",'','')")

genkey()
#ENCRYPTION
root = tk.Tk()
root.withdraw()
file = filedialog.askopenfilename()
file_name = Path(file).stem
file = open(file, "rb")
raw = str(file.read())
encrypted = encrypt(raw, key)
print(encrypted)
file.close()
writeenc(encrypted)
compressenc(file_name)

#DECRYPTION
root = tk.Tk()
root.withdraw()
file = filedialog.askopenfilename()
file_name = Path(file).stem
extractenc(file_name)
decrypted = decrypt(encrypted, key)
print(decrypted)
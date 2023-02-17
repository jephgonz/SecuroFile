# LIBRARIES
import bcrypt
import binascii
import tkinter as tk
from tkinter import filedialog
from tkinter import *
from Crypto import Random
from Crypto.Cipher import AES
import subprocess
import mysql.connector
import zipfile
import os
import re

# Make a regular expression
# for validating an Email
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

# GLOBAL VARIABLES
list_files = ['cache/filename', 'cache/key', 'cache/enc']
user_id = ''
current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
FONT = ('Nirmala UI', 16, 'bold')

# FILE HEADER SIGNATURE
uni_key = b'9\xc8=L\xca\x8ap_\x02p\xdd\x00\noi\x94\x15}\xe8\xb5\xf0\xdaI\x04'
file_sig = '$securofile$'
file_sig_en = bcrypt.hashpw(file_sig.encode('utf8'), bcrypt.gensalt()).decode()

string = file_sig_en
print("String to be converted :", string)

file_sig_en_in_hex = bytes(string, "utf-16")
print("Converted to hex:", file_sig_en_in_hex)

file_sig_en_in_bytes = file_sig_en_in_hex.hex()
print("Converted to bytes:", file_sig_en_in_bytes)

file_sig_en_true = binascii.unhexlify(file_sig_en_in_bytes)
file_sig_en_true_de = file_sig_en_true.decode("utf-16")
print("Converted to true value:", file_sig_en_true_de)

file_sig_en_true_bytes = bytes(file_sig_en_true_de, "utf-8")
print("Converted true value to bytes:", file_sig_en_true_bytes)


# string = file_sig_en
# print("the string is:", string)
# in_bytes = bytes(string, "utf-8")
# print("string to byte:", in_bytes)
# hex_bytes = binascii.hexlify(in_bytes)
# print("hexlify converts the data to hexdecimal value :", hex_bytes)
# hex_str = hex_bytes.decode("ascii")
# print("This is the converted hex value:", hex_str)
# # To convert hex to bytes
# y=binascii.unhexlify(hex_str)
# # unhexlify converts hex value to bytes.
# print("This is the converts hex value to bytes:", y)

# GLOBAL FUNCTIONS
def database():
    global con, cursor
    con = mysql.connector.connect(host="localhost", user="root", password="", database="capstone")
    cursor = con.cursor()


# TKINTER INIT
class tkinterApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry("400x600")
        self.title("SecuroFile")
        self.resizable(width=False, height=False)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in (StartPage, Page1, Page2):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(StartPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


# LOGIN
class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")
        frame = Frame(self, width=350, height=550, bg="#292F36")
        frame.place(x=25, y=25)
        heading = Label(frame, text='LOGIN', fg="#FFFFFF", bg="#292F36", font=FONT)
        heading.grid(row=1, columnspan=2)
        EMAIL = StringVar()
        PASS = StringVar()
        lbl_username = Label(frame, text="Email:", font=FONT, bd=10, fg="#FFFFFF", bg="#292F36")
        lbl_username.grid(row=2)
        lbl_password = Label(frame, text="Password:", font=FONT, bd=10, fg="#FFFFFF", bg="#292F36")
        lbl_password.grid(row=3)
        email = Entry(frame, font=FONT, textvariable=EMAIL, width=19)
        email.grid(row=2, column=1)
        pass1 = Entry(frame, font=FONT, textvariable=PASS, width=19, show="*")
        pass1.grid(row=3, column=1)
        lbl_result = Label(frame, text="", font=FONT, fg="#FFFFFF", bg="#292F36")
        lbl_result.grid(row=4, columnspan=2)
        btn_login = Button(frame, font=FONT, text="Login",
                           command=lambda: login_user(EMAIL.get(), PASS.get(), lbl_result), fg="#FFFFFF", bg="#4ECDC4")
        btn_login.grid(row=5, columnspan=2)
        button2 = Button(frame, font=FONT, text="Register", command=lambda: controller.show_frame(Page1), fg="#FFFFFF",
                         bg="#FF6B6B")
        button2.grid(row=6, columnspan=2)

        def login_user(EMAIL, PASS, lbl_result):
            database()
            print("Email: " + str(EMAIL))
            print("Password: " + str(PASS))
            hashed = ""
            if EMAIL == "" or PASS == "":
                lbl_result.config(text="Please complete the required field!", fg="orange")
            else:
                queryable = "SELECT * FROM `users` WHERE email='" + EMAIL + "'"
                cursor.execute(queryable)
                if cursor.fetchone() is not None:
                    queryable = "SELECT * FROM `users` WHERE email='" + EMAIL + "'"
                    cursor.execute(queryable)
                    table2 = cursor.fetchall()
                    for row2 in table2:
                        hashed = row2[5]
                        print("PW Hash: " + str(row2[5]))
                        global user_id
                        user_id = row2[0]
                        print("User ID: " + str(user_id))
                    if bcrypt.checkpw(PASS.encode(), hashed.encode()):
                        controller.show_frame(Page2)
                    else:
                        lbl_result.config(text="Password incorrect", fg="red")
                else:
                    lbl_result.config(text="Email not registered", fg="red")


# REGISTER
class Page1(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")
        frame = Frame(self, width=350, height=550, bg="#292F36")
        frame.place(x=25, y=25)
        heading = Label(frame, text='REGISTER', fg="#FFFFFF", bg="#292F36", font=FONT)
        heading.grid(row=1, columnspan=2)
        FNAME = StringVar()
        MNAME = StringVar()
        LNAME = StringVar()
        EMAIL = StringVar()
        PASS = StringVar()
        RPASS = StringVar()
        lbl_firstname = Label(frame, text="First name:", font=FONT, bd=5, fg="#FFFFFF", bg="#292F36")
        lbl_firstname.grid(row=2)
        lbl_firstname = Label(frame, text="Middle name:", font=FONT, bd=5, fg="#FFFFFF", bg="#292F36")
        lbl_firstname.grid(row=3)
        lbl_lastname = Label(frame, text="Last name:", font=FONT, bd=5, fg="#FFFFFF", bg="#292F36")
        lbl_lastname.grid(row=4)
        lbl_username = Label(frame, text="Email:", font=FONT, bd=5, fg="#FFFFFF", bg="#292F36")
        lbl_username.grid(row=5)
        lbl_password = Label(frame, text="Password:", font=FONT, bd=5, fg="#FFFFFF", bg="#292F36")
        lbl_password.grid(row=6)
        lbl_password = Label(frame, text="Repeat password:", font=FONT, bd=5, fg="#FFFFFF", bg="#292F36")
        lbl_password.grid(row=7)
        lbl_result = Label(frame, text="", font=FONT, fg="#FFFFFF", bg="#292F36")
        lbl_result.grid(row=8, columnspan=2)
        fname = Entry(frame, font=FONT, textvariable=FNAME, width=14)
        fname.grid(row=2, column=1)
        mname = Entry(frame, font=FONT, textvariable=MNAME, width=14)
        mname.grid(row=3, column=1)
        lname = Entry(frame, font=FONT, textvariable=LNAME, width=14)
        lname.grid(row=4, column=1)
        email = Entry(frame, font=FONT, textvariable=EMAIL, width=14)
        email.grid(row=5, column=1)
        pass1 = Entry(frame, font=FONT, textvariable=PASS, width=14, show="*")
        pass1.grid(row=6, column=1)
        rpass1 = Entry(frame, font=FONT, textvariable=RPASS, width=14, show="*")
        rpass1.grid(row=7, column=1)
        btn_register = Button(frame, font=FONT, text="Register", state=NORMAL,
                              command=lambda: register_user(FNAME.get(), MNAME.get(), LNAME.get(), EMAIL.get(),
                                                            PASS.get(), RPASS.get(), lbl_result, btn_register),
                              fg="#FFFFFF", bg="#4ECDC4")
        btn_register.grid(row=9, columnspan=2)
        button2 = Button(frame, font=FONT, text="Login", command=lambda: controller.show_frame(StartPage), fg="#FFFFFF",
                         bg="#FF6B6B")
        button2.grid(row=10, columnspan=2)

        def register_user(FNAME, MNAME, LNAME, EMAIL, PASS, RPASS, lbl_result, btn_register):
            database()
            if FNAME == "" or MNAME == "" or LNAME == "" or EMAIL == "" or PASS == "" or RPASS == "":
                lbl_result.config(text="Please complete the required field!", fg="orange")
            else:
                if PASS == RPASS:
                    queryemail = "SELECT * FROM `users` WHERE email='" + EMAIL + "'"
                    cursor.execute(queryemail)
                    if cursor.fetchone() is not None:
                        lbl_result.config(text="Email is already registered", fg="red")
                    else:
                        PASS = bcrypt.hashpw(PASS.encode('utf8'), bcrypt.gensalt())
                        cursor.execute(
                            "INSERT INTO `users` (fname, mname, lname, email, password) VALUES(%s, %s, %s, %s, %s)",
                            (str(FNAME), str(MNAME), str(LNAME), str(EMAIL), str(PASS.decode("utf-8"))))
                        lbl_result.config(text="Successfully Created!", fg="green")
                        con.commit()
                        cursor.close()
                        con.close()
                        btn_register['state'] = DISABLED
                else:
                    lbl_result.config(text="Password does not match!", fg="red")


# MAIN APP
class Page2(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")
        frame = Frame(self, width=350, height=550, bg="#292F36")
        frame.place(x=25, y=25)
        btn_encrypt = Button(frame, font=FONT, text="ENCRYPT", state=NORMAL, command=lambda: (encrypt_file(key)),
                             fg="#FFFFFF", bg="#4ECDC4")
        btn_encrypt.grid(row=1, columnspan=2)
        btn_decrypt = Button(frame, font=FONT, text="DECRYPT", state=NORMAL, command=lambda: (decrypt_file()),
                             fg="#FFFFFF", bg="#FF6B6B")
        btn_decrypt.grid(row=2, columnspan=2)

        btn_decrypt = Button(frame, font=FONT, text="REGISTER DEVICE", state=NORMAL,
                             command=lambda: (regdev(current_machine_id)),
                             fg="#FFFFFF", bg="#FF6B6B")
        btn_decrypt.grid(row=3, columnspan=2)

        listbox = Listbox(frame)
        listbox.grid(row=4, columnspan=2)
        listbox.insert(1, "sample")

        entrybox = Entry(frame)
        entrybox.grid(row=5, columnspan=2)

        submitButton = Button(frame, font=FONT, text="submit", state=NORMAL, command=lambda: (submit()))
        submitButton.grid(row=6, columnspan=2)
        addButton = Button(frame, font=FONT, text="add", state=NORMAL, command=lambda: (add()))
        addButton.grid(row=7, columnspan=2)
        delButton = Button(frame, font=FONT, text="delete", state=NORMAL, command=lambda: (delete()))
        delButton.grid(row=8, columnspan=2)

        def submit():
            try:
                print("You selected: " + listbox.get(listbox.curselection()))
            except:
                print("No item selected")

        def add():
            if re.fullmatch(regex, entrybox.get()):
                listbox.insert(listbox.size(), entrybox.get())
                print("Email added")
            else:
                print("Invalid Email")

        def delete():
            try:
                print("You deleted: " + listbox.get(listbox.curselection()))
                listbox.delete(listbox.delete(listbox.curselection()))
            except:
                print("No item selected/Process done")

        def regdev(current_machine_id):
            database()
            print("Current Device ID: " + str(current_machine_id))
            query = "select * from devices"
            cursor.execute(query)
            table = cursor.fetchall()
            match = 0
            for row in table:
                if current_machine_id == str(row[2]):
                    match = 1
                    print("Device already exist.")
                    break
            if match == 0:
                sql = "INSERT INTO `devices`(`user_id`, `deviceID`) VALUES (%s,%s)"
                val = ("" + str(user_id) + "", "" + current_machine_id + "")
                cursor.execute(sql, val)
                con.commit()
                print("Device registered successfully.")

        def compressenc(file_name):
            with zipfile.ZipFile('encrypted/' + file_name + '.enc', 'w') as zipF:
                for file in list_files:
                    zipF.write(file, compress_type=zipfile.ZIP_DEFLATED)

        def extractenc(file_path):
            with zipfile.ZipFile(file_path, mode="r") as archive:
                archive.extractall("")

        def pad(s):
            return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

        def encrypt(message, key, key_size=256):
            message = pad(message)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return iv + cipher.encrypt(message)

        def decrypt(ciphertext, key):
            iv = ciphertext[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext[AES.block_size:])
            return plaintext.rstrip(b"\0")

        def fheadwrite(file_name):
            with open('encrypted/' + file_name + '.enc', 'rb') as fo:
                plaintext = fo.read()
            tow = plaintext.hex()
            newtow = file_sig_en_in_bytes + tow
            b = newtow[244:-2]
            c = newtow[0:244]
            d = binascii.unhexlify(c)
            e = d.decode("utf-16")
            print(e)
            tow2 = bytes.fromhex(b)
            newtow2 = bytes.fromhex(newtow)
            enc2 = encrypt(newtow2, uni_key)
            with open("ZIP NO FILE SIG.zip", 'wb') as writeenc:
                writeenc.write(tow2)
            with open("FILE SIG AND ENCRYPTED.enc", 'wb') as writeenc:
                writeenc.write(enc2)
            with open("FILE SIG AND ENCRYPTED.enc", 'rb') as fo:
                encdata = fo.read()
            dec = decrypt(encdata, uni_key)
            with open("WITH FILE SIG ONLY.enc", 'wb') as writeenc:
                writeenc.write(dec)
            with open("WITH FILE SIG ONLY.enc", 'rb') as fo:
                newtow2 = fo.read()
            h = newtow2[244:-2]
            with open("ZIP NO FILE SIG PROCESSED.zip", 'wb') as writeenc:
                writeenc.write(h)

        def encrypt_file(key):
            file_path = filedialog.askopenfilename()
            head, tail = os.path.split(file_path)
            root, ext = os.path.splitext(tail)
            print("File Name: " + str(tail))
            print("File Directory: " + str(head))
            print("File Path: " + str(file_path))
            with open(file_path, 'rb') as fo:
                plaintext = fo.read()
            enc = encrypt(plaintext, key)
            with open('cache/filename', 'wb') as filename:
                filename.write(tail.encode())
            with open("cache/enc", 'wb') as fo:
                fo.write(enc)
            compressenc(root)
            # fheadwrite(root)
            print("Succesfully Encrypted!")

        def decrypt_file():
            file_path = filedialog.askopenfilename()
            head, tail = os.path.split(file_path)
            print("File Name: " + str(tail))
            print("File Directory: " + str(head))
            print("File Path: " + str(file_path))
            extractenc(file_path)
            with open("cache/enc", 'rb') as fo1:
                ciphertext = fo1.read()
            with open("cache/key", 'rb') as fo2:
                fkey = fo2.read()
                print("Key: " + str(fkey))
            with open("cache/filename", 'rb') as fo3:
                file_name = fo3.read()
                print("File Name: " + str(file_name))
            dec = decrypt(ciphertext, fkey)
            file = file_name
            with open("decrypted/" + str(file.decode("utf-8")), 'wb') as fo:
                fo.write(dec)
            print("Succesfully Decrypted!")

        key = os.urandom(24)
        print("Generated Key: " + str(key))
        with open('cache/key', 'wb') as filekey:
            filekey.write(key)


# DRIVER CODE
app = tkinterApp()
app.mainloop()

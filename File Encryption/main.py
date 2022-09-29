# LIBRARIES
import bcrypt
import tkinter as tk
from tkinter import *
from Crypto import Random
from Crypto.Cipher import AES
import subprocess
import mysql.connector
import zipfile
import os

# GLOBAL VARIABLES
list_files = ['cache/header', 'cache/key', 'cache/enc']
user_id = ''
current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
FONT = ('Nirmala UI', 16, 'bold')

# GLOBAL FUNCTIONS
def database():
    global con, cursor
    con = mysql.connector.connect(host="localhost", user="root", password="", database="capstone")
    cursor = con.cursor()

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
        val = ("" + user_id + "", "" + current_machine_id + "")
        cursor.execute(sql, val)
        con.commit()
        print("Device registered successfully.")

def updateDevStat(devId, status):
    if status == "Active":
        status = "Active"
    else:
        status = "Inactive"
    sql = "UPDATE `devices` SET `date_modified` = CURRENT_TIMESTAMP, `status` = '" + status + "' WHERE `devices`. `dev_id` = " + devId + ""
    cursor.execute(sql)
    con.commit()

def compressenc(file_name):
    with zipfile.ZipFile('encrypted/' + file_name + '.enc', 'w') as zipF:
        for file in list_files:
            zipF.write(file, compress_type=zipfile.ZIP_DEFLATED)

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
        btn_encrypt = Button(frame, font=FONT, text="ENCRYPT", state=NORMAL, command=lambda: (encrypt_file('links.txt', key)),
                             fg="#FFFFFF", bg="#4ECDC4")
        btn_encrypt.grid(row=1, columnspan=2)
        btn_decrypt = Button(frame, font=FONT, text="DECRYPT", state=NORMAL, command=lambda: (decrypt_file('links.txt.enc', key)),
                             fg="#FFFFFF", bg="#FF6B6B")
        btn_decrypt.grid(row=2, columnspan=2)

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

        def encrypt_file(file_name, key):
            with open(file_name, 'rb') as fo:
                plaintext = fo.read()
            enc = encrypt(plaintext, key)
            with open(file_name + ".enc", 'wb') as fo:
                fo.write(enc)

        def decrypt_file(file_name, key):
            with open(file_name, 'rb') as fo:
                ciphertext = fo.read()
            dec = decrypt(ciphertext, key)
            with open(file_name[:-4], 'wb') as fo:
                fo.write(dec)

        key = os.urandom(24)
        print("Generated Key: " + str(key))
        with open('key', 'wb') as filekey:
            filekey.write(key)

# DRIVER CODE
app = tkinterApp()
app.mainloop()

# LIBRARIES
import base64
import bcrypt
import hashlib
import tkinter as tk
from tkinter import ttk
from tkinter import *
from tkinter import filedialog
from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography.fernet import Fernet
import subprocess
import mysql.connector
import zipfile
from pathlib import Path

# DB CONNECTION
con = mysql.connector.connect(host="localhost", user="root", password="", database="capstone")
cursor = con.cursor()

# TEST GET USERS WITH DEVICES
query = "select * from user_devices"
cursor.execute(query)
table = cursor.fetchall()
for row in table:
    print(row[0])
    print(row[1])
    print(row[2])
    print(row[3])
    print(row[4])
print("TEST GET USERS WITH DEVICES DONE.")

# VARIABLES
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
list_files = ['cache/header', 'cache/key', 'cache/enc']
key = 'placeholder'
user_id = '1'  # ADD USER_ID AFTER LOGIN
current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
print(current_machine_id)
print("TEST GET CURRENT MACHINE ID DONE.")


# --------------------- INIT ---------------------
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


# -------------------- LOGIN ---------------------
class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#fff")
        frame = Frame(self, width=350, height=550, bg="red")
        frame.place(x=25, y=25)

        heading = Label(frame, text='Login', fg="#000", bg="white", font=('Arial', 24, 'bold'))
        heading.grid(row=1)

        EMAIL = StringVar()
        PASS = StringVar()

        lbl_username = Label(frame, text="Email:", font=('arial', 18), bd=18, bg="#fff")
        lbl_username.grid(row=2)
        lbl_password = Label(frame, text="Password:", font=('arial', 18), bd=18, bg="#fff")
        lbl_password.grid(row=3)

        email = Entry(frame, font=('arial', 20), textvariable=EMAIL, width=15)
        email.grid(row=2, column=1)
        pass1 = Entry(frame, font=('arial', 20), textvariable=PASS, width=15, show="*")
        pass1.grid(row=3, column=1)
        lbl_result = Label(frame, text="", font=('arial', 18), bg="#fff")
        lbl_result.grid(row=4, columnspan=2)

        btn_login = Button(frame, font=('arial', 20), text="Login",
                           command=lambda: login_user(EMAIL.get(), PASS.get(), lbl_result))
        btn_login.grid(row=5, columnspan=2)

        button2 = Button(frame, font=('arial', 20), text="Register", command=lambda: controller.show_frame(Page1))
        button2.grid(row=6, columnspan=2)

        def database():
            global con, cursor
            con = mysql.connector.connect(host="localhost", user="root", password="", database="capstone")
            cursor = con.cursor()

        def login_user(EMAIL, PASS, lbl_result):
            database()
            print(EMAIL)
            print(PASS)
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
                        print(row2[5])
                    if bcrypt.checkpw(PASS.encode(), hashed.encode()):
                        lbl_result.config(text="It matches!", fg="green")
                        controller.show_frame(Page2)
                    else:
                        lbl_result.config(text="Didn't match!", fg="red")
                else:
                    lbl_result.config(text="Email not registered", fg="red")


# ------------------- REGISTER -------------------
class Page1(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#fff")
        frame = Frame(self, width=350, height=550, bg="red")
        frame.place(x=25, y=25)
        # img = PhotoImage(file='media/user.png')
        # Label(frame, image=img, bg='white').place(x=0, y=0)
        heading = Label(frame, text='Register', fg="#000", bg="white", font=('Arial', 24, 'bold'))
        heading.grid(row=1)

        FNAME = StringVar()
        MNAME = StringVar()
        LNAME = StringVar()
        EMAIL = StringVar()
        PASS = StringVar()
        RPASS = StringVar()

        lbl_firstname = Label(frame, text="First name:", font=('arial', 18), bd=18)
        lbl_firstname.grid(row=2)
        lbl_firstname = Label(frame, text="Middle name:", font=('arial', 18), bd=18)
        lbl_firstname.grid(row=3)
        lbl_lastname = Label(frame, text="Last name:", font=('arial', 18), bd=18)
        lbl_lastname.grid(row=4)
        lbl_username = Label(frame, text="Email:", font=('arial', 18), bd=18)
        lbl_username.grid(row=5)
        lbl_password = Label(frame, text="Password:", font=('arial', 18), bd=18)
        lbl_password.grid(row=6)
        lbl_password = Label(frame, text="Repeat password:", font=('arial', 18), bd=18)
        lbl_password.grid(row=7)
        lbl_result = Label(frame, text="", font=('arial', 18))
        lbl_result.grid(row=8, columnspan=2)

        fname = Entry(frame, font=('arial', 20), textvariable=FNAME, width=15)
        fname.grid(row=2, column=1)
        mname = Entry(frame, font=('arial', 20), textvariable=MNAME, width=15)
        mname.grid(row=3, column=1)
        lname = Entry(frame, font=('arial', 20), textvariable=LNAME, width=15)
        lname.grid(row=4, column=1)
        email = Entry(frame, font=('arial', 20), textvariable=EMAIL, width=15)
        email.grid(row=5, column=1)
        pass1 = Entry(frame, font=('arial', 20), textvariable=PASS, width=15, show="*")
        pass1.grid(row=6, column=1)
        rpass1 = Entry(frame, font=('arial', 20), textvariable=RPASS, width=15, show="*")
        rpass1.grid(row=7, column=1)

        btn_register = Button(frame, font=('arial', 20), text="Register", state=NORMAL,
                              command=lambda: register_user(FNAME.get(), MNAME.get(), LNAME.get(), EMAIL.get(),
                                                            PASS.get(), RPASS.get(), lbl_result, btn_register))
        btn_register.grid(row=9, columnspan=2)

        button2 = Button(frame, font=('arial', 20), text="Login", command=lambda: controller.show_frame(StartPage))
        button2.grid(row=10, columnspan=2)

        def database():
            global con, cursor
            con = mysql.connector.connect(host="localhost", user="root", password="", database="capstone")
            cursor = con.cursor()

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


# ------------------- MAIN APP -------------------
class Page2(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = ttk.Label(self, text="Page 2", font=('arial', 20))
        label.grid(row=0, column=4, padx=10, pady=10)

        # button to show frame 2 with text
        # layout2
        button1 = ttk.Button(self, text="Page 1",
                             command=lambda: controller.show_frame(Page1))

        # putting the button in its place by
        # using grid
        button1.grid(row=1, column=1, padx=10, pady=10)

        # button to show frame 3 with text
        # layout3
        button2 = ttk.Button(self, text="Startpage",
                             command=lambda: controller.show_frame(StartPage))

        # putting the button in its place by
        # using grid
        button2.grid(row=2, column=1, padx=10, pady=10)


# ----------------- DRIVER CODE ------------------
app = tkinterApp()
app.mainloop()


# -------------- START OF FUNCTIONS --------------
def database():
    global con, cursor
    con = mysql.connector.connect(host="localhost", user="root", password="", database="capstone")
    cursor = con.cursor()


def encrypt(raw, key):
    private_key = hashlib.sha256(key.encode('utf8')).digest()
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key=private_key, mode=AES.MODE_CFB, iv=iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc, key):
    private_key = hashlib.sha256(key.encode('utf8')).digest()
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
    with zipfile.ZipFile('encrypted/' + file_name + '.enc', 'w') as zipF:
        for file in list_files:
            zipF.write(file, compress_type=zipfile.ZIP_DEFLATED)


def extractenc(file_name):
    with zipfile.ZipFile('encrypted/' + file_name + '.enc', 'r') as zip_ref:
        zip_ref.extractall('')


def genkey():
    key = Fernet.generate_key()
    print(key)
    with open('cache/key', 'wb') as filekey:
        filekey.write(key)


def regdev(current_machine_id):
    database()
    print(current_machine_id)
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


# --------------- END OF FUNCTIONS ---------------

# ----------------- INITIATIONS ------------------
genkey()
regdev(current_machine_id)
updateDevStat('8', 'Inactive')

# ------------------ ENCRYPTION ------------------
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

# Compile File
compressenc(file_name)

# ------------------ DECRYPTION ------------------
root = tk.Tk()
root.withdraw()
file = filedialog.askopenfilename()
file_name = Path(file).stem

# Decompress Encrypted File
extractenc(file_name)

decrypted = decrypt(encrypted, key)
print(decrypted)

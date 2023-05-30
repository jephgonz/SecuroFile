# LIBRARIES
import binascii
import os
import pathlib
import re
import subprocess
import tkinter as tk
import zipfile
from tkinter import *
from tkinter import filedialog
import math, random
import bcrypt
import mysql.connector
from Crypto import Random
from Crypto.Cipher import AES

# Make a regular expression
# for validating an Email
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

# GLOBAL VARIABLES
list_files = ['cache/filename', 'cache/key', 'cache/enc', 'cache/recipient']
user_id = ''
cur_email = ''
current_machine_id = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
FONT = ('Nirmala UI', 16, 'bold')

# FILE HEADER SIGNATURE
uni_key = b'9\xc8=L\xca\x8ap_\x02p\xdd\x00\noi\x94\x15}\xe8\xb5\xf0\xdaI\x04'
file_sig = '$securofile$'

string = file_sig
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


# GLOBAL FUNCTIONS
def database():
    print("Connection Initialize to Database")
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
        for F in (StartPage, Page1, Page2, ContactPage, DevicePage):
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
        heading = Label(frame, text='Login', fg="#FFFFFF", bg="#292F36", font=FONT)
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
                        global cur_email
                        cur_email = EMAIL
                        print("User ID: " + str(user_id))
                    if bcrypt.checkpw(PASS.encode(), hashed.encode()):
                        pass1.delete(0, 'end')
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
        heading = Label(frame, text='Register', fg="#FFFFFF", bg="#292F36", font=FONT)
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

        heading = Label(frame, text='Select Recipients', fg="#FFFFFF", bg="#292F36", font=FONT)
        heading.grid(row=1, column=1)

        listbox = Listbox(frame, selectmode=MULTIPLE, width=57)
        listbox.grid(row=2, column=1)

        reButton = Button(frame, font=FONT, text="Refresh Contacts", state=NORMAL, command=lambda: (refresh()))
        reButton.grid(row=3, column=1)

        btn_encrypt = Button(frame, font=FONT, text="ENCRYPT", state=NORMAL, command=lambda: (encrypt_file(key)),
                             fg="#FFFFFF", bg="#4ECDC4")
        btn_encrypt.grid(row=4, column=1)
        btn_decrypt = Button(frame, font=FONT, text="DECRYPT", state=NORMAL, command=lambda: (decrypt_file()),
                             fg="#FFFFFF", bg="#FF6B6B")
        btn_decrypt.grid(row=5, column=1)

        # Using readlines()
        file1 = open('user/contacts.txt', 'r')
        Lines = file1.readlines()

        count = 0
        # Strips the newline character
        for line in Lines:
            count += 1
            listbox.insert(count, line.strip())

        buttonset = Button(frame, font=FONT, text="Contacts", command=lambda: controller.show_frame(ContactPage),
                           fg="#FFFFFF",
                           bg="#FF6B6B")
        buttonset.grid(row=6, column=1)

        buttonset = Button(frame, font=FONT, text="Devices", command=lambda: controller.show_frame(DevicePage),
                           fg="#FFFFFF",
                           bg="#FF6B6B")
        buttonset.grid(row=7, column=1)

        buttonlogout = Button(frame, font=FONT, text="Log Out", command=lambda: controller.show_frame(StartPage),
                              fg="#FFFFFF",
                              bg="#FF6B6B")
        buttonlogout.grid(row=8, column=1)

        def refresh():
            listbox.delete(0, tk.END)
            # Using readlines()
            file1 = open('user/contacts.txt', 'r')
            Lines = file1.readlines()

            count = 0
            # Strips the newline character
            for line in Lines:
                count += 1
                listbox.insert(count, line.strip())
            print("Contacts refreshed")

        def packenc(file_name):
            with zipfile.ZipFile('encrypted/' + file_name + '.enc', 'w') as zipF:
                for file in list_files:
                    zipF.write(file, compress_type=zipfile.ZIP_DEFLATED)

        def unpackenc(file_path):
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

        def encrypt_file(key):
            try:
                email = [cur_email]
                emailh = []
                for index in listbox.curselection():
                    email.insert(index, listbox.get(index))

                for index in email:
                    print(index)
                    index = str(bcrypt.hashpw(index.encode('utf8'), bcrypt.gensalt()).decode("utf-8"))
                    print(index)
                    emailh.append(str(index))

                for index in emailh:
                    print(index)

                with open('cache/recipient', 'w') as f:
                    for line in emailh:
                        f.write(line)
                        f.write('\n')
                print("Email(s) submitted")

                file_path = filedialog.askopenfilename()
                fpath = pathlib.Path(file_path)

                head, tail = os.path.split(file_path)
                root, ext = os.path.splitext(tail)
                print("File Name: " + str(tail))
                print("File Directory: " + str(head))
                print("File Path: " + str(file_path))

                with open(file_path, 'rb') as fo:
                    plaintext1 = fo.read()
                enc = encrypt(plaintext1, key)
                with open('cache/key', 'rb') as fo:
                    plaintext2 = fo.read()
                kenc = encrypt(plaintext2, uni_key)
                with open('cache/recipient', 'rb') as fo:
                    plaintext3 = fo.read()
                renc = encrypt(plaintext3, uni_key)
                with open('cache/filename', 'wb') as filename:
                    filename.write(tail.encode())
                with open("cache/enc", 'wb') as fo:
                    fo.write(enc)
                with open("cache/key", 'wb') as fo:
                    fo.write(kenc)
                with open("cache/recipient", 'wb') as fo:
                    fo.write(renc)
                packenc(root)

                print("Succesfully Encrypted!")
                tk.messagebox.showinfo(title="SecuroFile", message="Succesfully Encrypted!")
            except:
                print("No item selected")

        def decrypt_file():
            try:
                file_path = filedialog.askopenfilename()
                fpath = pathlib.Path(file_path)
                head, tail = os.path.split(file_path)
                print("File Name: " + str(tail))
                print("File Directory: " + str(head))
                print("File Path: " + str(file_path))

                print("Unpacking")
                unpackenc(file_path)

                # Decrypt Recipients
                with open('cache/recipient', 'rb') as fo:
                    plaintext3 = fo.read()
                renc = decrypt(plaintext3, uni_key)
                with open("cache/recipient", 'wb') as fo:
                    fo.write(renc)

                # Using readlines()
                file1 = open('cache/recipient', 'r')
                Lines = file1.readlines()

                email = []
                # Strips the newline character
                for line in Lines:
                    email.append(line.strip())
                print(email)

                isDecrypted = False
                for x in email:
                    if bcrypt.checkpw(cur_email.encode(), x.encode()):
                        print("Current email match!")
                        database()
                        queryable = "SELECT deviceID FROM `user_devices` WHERE email = '" + cur_email + "'"
                        cursor.execute(queryable)
                        table = cursor.fetchall()
                        for row in table:
                            if row[0] == current_machine_id:
                                print("Current Device match!")
                                print("Start Decrypting")
                                with open("cache/enc", 'rb') as fo1:
                                    ciphertext = fo1.read()
                                with open('cache/key', 'rb') as fo:
                                    plaintext2 = fo.read()
                                kenc = decrypt(plaintext2, uni_key)
                                with open("cache/key", 'wb') as fo:
                                    fo.write(kenc)
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
                                isDecrypted = True
                            else:
                                print("Current Device doesnt match!")
                    else:
                        print("Current email doesnt match!")
                if isDecrypted:
                    print("Succesfully Decrypted!")
                    tk.messagebox.showinfo(title="SecuroFile", message="Succesfully Decrypted!")
                else:
                    print("Access Denied!")
                    tk.messagebox.showinfo(title="SecuroFile", message="Access Denied!")
            except:
                print("No item selected")


# KEY GENERATION
key = os.urandom(24)
print("Generated Key: " + str(key))
with open('cache/key', 'wb') as filekey:
    filekey.write(key)


class ContactPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")
        frame = Frame(self, width=350, height=550, bg="#292F36")
        frame.place(x=25, y=25)

        heading = Label(frame, text='Contacts', fg="#FFFFFF", bg="#292F36", font=FONT)
        heading.grid(row=1, column=1)

        listbox = Listbox(frame, selectmode=MULTIPLE, width=57)
        listbox.grid(row=2, column=1)

        # Using readlines()
        file1 = open('user/contacts.txt', 'r')
        Lines = file1.readlines()

        count = 0
        # Strips the newline character
        for line in Lines:
            count += 1
            listbox.insert(count, line.strip())

        entrybox = Entry(frame, width=57)
        entrybox.grid(row=3, column=1)

        addButton = Button(frame, font=FONT, text="Add", state=NORMAL, command=lambda: (add()))
        addButton.grid(row=4, column=1)
        delButton = Button(frame, font=FONT, text="Delete", state=NORMAL, command=lambda: (delete()))
        delButton.grid(row=5, column=1)

        buttonset = Button(frame, font=FONT, text="Back", command=lambda: controller.show_frame(Page2),
                           fg="#FFFFFF",
                           bg="#FF6B6B")
        buttonset.grid(row=6, column=1)

        def add():
            if re.fullmatch(regex, entrybox.get()):
                listbox.insert(listbox.size(), entrybox.get())

                all_items = listbox.get(0, tk.END)

                with open('user/contacts.txt', 'w') as f:
                    for line in all_items:
                        f.write(line)
                        f.write('\n')

                print("Email added")
                tk.messagebox.showinfo(title="SecuroFile", message="Email added.")
            else:
                print("Invalid Email")
                tk.messagebox.showinfo(title="SecuroFile", message="Invalid Email.")

        def delete():
            try:
                print("You deleted: " + listbox.get(listbox.curselection()))
                listbox.delete(listbox.curselection())

                all_items2 = listbox.get(0, tk.END)

                with open('user/contacts.txt', 'w') as f:
                    for line in all_items2:
                        f.write(line)
                        f.write('\n')

                print("Email deleted")
                tk.messagebox.showinfo(title="SecuroFile", message="Email deleted.")
            except:
                print("No item selected")
                tk.messagebox.showinfo(title="SecuroFile", message="No item selected.")


class DevicePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")
        frame = Frame(self, width=350, height=550, bg="#292F36")
        frame.place(x=25, y=25)

        heading = Label(frame, text='Device List', fg="#FFFFFF", bg="#292F36", font=FONT)
        heading.grid(row=1, column=1)
        heading = Label(frame, text="Current Device: " + current_machine_id, fg="#FFFFFF", bg="#292F36",
                        font=('Nirmala UI', 9, 'bold'))
        heading.grid(row=2, column=1)

        listbox = Listbox(frame, width=57)
        listbox.grid(row=3, column=1)

        listbox.insert(0, "REFRESH TO REVEAL DEVICES")

        reButton = Button(frame, font=FONT, text="Refresh", state=NORMAL, command=lambda: (refresh()))
        reButton.grid(row=4, column=1)

        addButton = Button(frame, font=FONT, text="Register Device", state=NORMAL,
                           command=lambda: (regdev(current_machine_id)))
        addButton.grid(row=5, column=1)
        delButton = Button(frame, font=FONT, text="Remove", state=NORMAL, command=lambda: (delete()))
        delButton.grid(row=6, column=1)

        buttonset = Button(frame, font=FONT, text="Back", command=lambda: controller.show_frame(Page2),
                           fg="#FFFFFF",
                           bg="#FF6B6B")
        buttonset.grid(row=7, column=1)

        def refresh():
            listbox.delete(0, tk.END)
            print("Start Get Devices")
            database()
            global cur_email
            queryable = "SELECT deviceID FROM `user_devices` WHERE email = '" + cur_email + "'"
            cursor.execute(queryable)
            table = cursor.fetchall()
            for row in table:
                print(row)
                listbox.insert(0, row[0])
            print("Devices Refreshed")

        def delete():
            try:
                devstr = listbox.get(listbox.curselection())
                print("You deleted: " + devstr)
                listbox.delete(listbox.curselection())
                database()
                query = "DELETE FROM devices WHERE user_id = '" + str(user_id) + "' AND deviceID = '" + devstr + "'"
                cursor.execute(query)
                con.commit()
                print("Device Removed")
                tk.messagebox.showinfo(title="SecuroFile", message="Device removed successfully.")

            except:
                print("Something went wrong")

        def regdev(current_machine_id):
            database()
            print("Current Device ID: " + str(current_machine_id))
            query = "select * from devices"

            query2 = "SELECT COUNT(email) FROM `user_devices` WHERE email = '" + cur_email + "'"

            cursor.execute(query)
            table = cursor.fetchall()
            cursor.execute(query2)
            table2 = cursor.fetchall()
            count = 0
            for row2 in table2:
                count = row2[0]

            print("Number of Devices Registered to the Account: " + str(count))

            if count < 3:
                match = 0
                for row in table:
                    if current_machine_id == str(row[2]):
                        match = 1
                        print("Device already exist.")
                        tk.messagebox.showinfo(title="SecuroFile", message="Device already exist.")
                        break
                if match == 0:
                    sql = "INSERT INTO `devices`(`user_id`, `deviceID`) VALUES (%s,%s)"
                    val = ("" + str(user_id) + "", "" + current_machine_id + "")
                    cursor.execute(sql, val)
                    con.commit()
                    # part when to insert the added device to listbox
                    listbox.insert(listbox.size(), current_machine_id)
                    print("Device registered successfully.")
                    tk.messagebox.showinfo(title="SecuroFile", message="Device registered successfully.")
            else:
                print("Maximum devices allocated.")
                tk.messagebox.showinfo(title="SecuroFile", message="Maximum devices allocated.")

        def generateOTP():
            # Declare a digits variable
            # which stores all digits
            digits = "0123456789"
            OTP = ""
            # length of password can be changed
            # by changing value in range
            for i in range(4):
                OTP += digits[math.floor(random.random() * 10)]
            return OTP


# DRIVER CODE
app = tkinterApp()
app.mainloop()

#libraries
import os
import re
import subprocess
import random2 as random
import keyboard as bkey
from email.message import EmailMessage
import smtplib
import tkinter as tk
import zipfile
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import bcrypt
import mysql.connector
from Crypto import Random
from Crypto.Cipher import AES
import traceback
from PIL import Image, ImageTk
from pathlib import Path
from pynput import keyboard
import sys
sys.path.append('../customlib')
from customlib import tkPDFViewer as pdf
import pyzipper

#global variables
uni_key = b'9\xc8=L\xca\x8ap_\x02p\xdd\x00\noi\x94\x15}\xe8\xb5\xf0\xdaI\x04'
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
list_files = ['cache/key', 'cache/enc', 'cache/recipient']
user_id = ''
current_email = ''
isVerified = False
tempOTP = 000000
Heading = ('Nirmala UI', 24, 'bold')
Heading2 = ('Nirmala UI', 20, 'bold')
Heading3 = ('Nirmala UI', 30, 'bold')
FONT = ('Nirmala UI', 14, 'bold')
FONTR = ('Nirmala UI', 14)
Small = ('Nirmala UI', 11, 'bold')
SmallR = ('Nirmala UI', 11)
OTP = ('Nirmala UI', 20)
BGCOL = "#27374D"
tempquery = ''

#OTP email settings
EMAIL_ADDRESS = 'jrgmillan23@gmail.com'
EMAIL_PASSWORD = 'jukphpbakxevdxhs'

#generate temp key
key = os.urandom(32)
print(key)
permakey1 = b'securofilekey'
permakey2 = permakey1.decode('utf-8')

def gennewkey():
    global key
    key = os.urandom(32)
    with open('cache/key', 'wb') as filekey:
        filekey.write(key)

#global functions
def database():
    try:
        print("Database Connection Established")
        global con, cursor
        con = mysql.connector.connect(host="capstonedb-capstone.a.aivencloud.com", port="23958", user="avnadmin", password="AVNS_b4dbBAXNWbKgOOtz31T", database="capstone")
        cursor = con.cursor()
    except:
        tk.messagebox.showinfo(title="SecuroFile", message="No internet connection.")

def getHardwareId():
    this = str(subprocess.check_output('wmic csproduct get uuid'), 'utf-8').split('\n')[1].strip()
    return this

#keyboard listener
def on_press(key):
    v1.img_object_li.clear()

listener1 = keyboard.Listener(on_press=on_press)
print("Listener Start")
listener1.start()

keytb="print_screen" #The key you want to block
bkey.block_key(keytb)

v1=pdf.ShowPdf()

#main app code
class SecuroFileApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry("1280x720")
        self.title("SecuroFile")
        self.resizable(width=False, height=False)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in (Login, NewAccountDeviceRegistration, Register, RActivation, Main, Contacts, Verification, Device, AskEmail, Verification2, ResetPassword):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(Login)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

#login
class Login(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.configure(bg="#27374D")

        load = Image.open("assets/bg.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Login', fg="#FFFFFF", bg=BGCOL, font=Heading)
        heading.place(x=50,y=100)
        EMAIL = StringVar()
        PASS = StringVar()
        lbl_username = Label(self, text="Email", font=FONT, bd=10, fg="#FFFFFF", bg=BGCOL)
        lbl_username.place(x=40, y=200)
        lbl_password = Label(self, text="Password", font=FONT, bd=10, fg="#FFFFFF", bg=BGCOL)
        lbl_password.place(x=40, y=300)
        email = Entry(self, font=FONTR, textvariable=EMAIL, width=36)
        email.place(x=50, y=250)
        pass1 = Entry(self, font=FONTR, textvariable=PASS, width=36, show="*")
        pass1.place(x=50, y=350)
        lbl_result = Label(self, text="", font=Small, fg="#FFFFFF", bg=BGCOL)
        lbl_result.place(x=50, y=390)

        button3 = Button(self, font=Small, text="Forgotten your password?", command=lambda: retoforpas(), fg="#30A2FF",
                         bg="#27374D", height=1, width=20, borderwidth=0)
        button3.place(x=50, y=420)

        btn_login = Button(self, font=FONT, text="Log In", command=lambda: login_user(EMAIL.get(), PASS.get(), lbl_result), fg="#FFFFFF", bg="#30A2FF", height=1, width=20)
        btn_login.place(x=120, y=480)
        button2 = Button(self, font=FONT, text="Register", command=lambda: retoreg(), fg="#000000", bg="#DDE6ED", height=1, width=20)
        button2.place(x=120, y=530)

        def retoforpas():
            controller.show_frame(AskEmail)
            lbl_result.config(text="")

        def retoreg():
            controller.show_frame(Register)
            lbl_result.config(text="")

        def loginAlert():
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                msg = EmailMessage()
                msg['Subject'] = 'Login alert'
                msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                msg['To'] = current_email
                msg.set_content('Your account was recently logged into a device: ' + getHardwareId() + '.')
                smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

        def login_user(EMAIL, PASS, lbl_result):
            print("Verification: "+str(isVerified))
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
                        print("Password Hash: " + str(row2[5]))
                        global user_id
                        user_id = row2[0]
                        global current_email
                        current_email = EMAIL
                        print("User ID: " + str(user_id))
                    if bcrypt.checkpw(PASS.encode(), hashed.encode()):
                        database()
                        query2 = "SELECT COUNT(email) FROM `user_devices` WHERE email = '" + current_email + "'"
                        cursor.execute(query2)
                        table2 = cursor.fetchall()
                        count = 0
                        for row2 in table2:
                            count = row2[0]
                        if count == 0:
                            controller.show_frame(NewAccountDeviceRegistration)
                            pass1.delete(0, 'end')
                            gennewkey()
                            lbl_result.config(text="")
                            loginAlert()
                        else:
                            controller.show_frame(Main)
                            pass1.delete(0, 'end')
                            gennewkey()
                            lbl_result.config(text="")
                            loginAlert()
                    else:
                        lbl_result.config(text="Password incorrect", fg="red")
                else:
                    lbl_result.config(text="Email not registered", fg="red")

class NewAccountDeviceRegistration(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")

        load = Image.open("assets/newuser.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Device Registration', fg="#ffffFF", bg="#292f36", font=Heading3)
        heading.place(x=455,y=70)
        lbl_drotp = Label(self, text="We detected that your account dont have a registered device, please register this device to continue using SecuroFile", font=FONT, fg="#FFFFFF", bg="#292f36")
        lbl_drotp.place(x=135, y=420)
        btn_register = Button(self, font=FONT, text="Register Device", state=NORMAL, command=lambda:regDevice(), fg="#FFFFFF", bg="#4ECDC4", borderwidth=0, height=2, width=17)
        btn_register.place(x=540, y=500)

        def regDevice():
            database()
            print("Current Device ID: " + str(getHardwareId()))
            sql = "INSERT INTO `devices`(`user_id`, `deviceID`) VALUES (%s,%s)"
            val = ("" + str(user_id) + "", "" + getHardwareId() + "")
            cursor.execute(sql, val)
            con.commit()
            controller.show_frame(Main)
            tk.messagebox.showinfo(title="SecuroFile", message="Device registered successfully.")
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                msg = EmailMessage()
                msg['Subject'] = 'A device has been added'
                msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                msg['To'] = current_email
                msg.set_content('Device: ' + getHardwareId() + ' has been added to your account.')
                smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

#register page
class Register(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.configure(bg="#27374D")

        load = Image.open("assets/rbg.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Register', fg="#000000", bg="#FFFFFF", font=Heading)
        heading.place(x=70,y=100)
        RFNAME = StringVar()
        RMNAME = StringVar()
        RLNAME = StringVar()
        REMAIL = StringVar()
        RPASS = StringVar()
        REPASS = StringVar()
        lbl_firstname = Label(self, text="First name", font=Small, bd=5, fg="#000000", bg="#FFFFFF")
        lbl_firstname.place(x=70, y=170)
        lbl_middlename = Label(self, text="Middle name", font=Small, bd=5, fg="#000000", bg="#FFFFFF")
        lbl_middlename.place(x=70, y=230)
        lbl_lastname = Label(self, text="Last name", font=Small, bd=5, fg="#000000", bg="#FFFFFF")
        lbl_lastname.place(x=70, y=285)
        lbl_username = Label(self, text="Email", font=Small, bd=5, fg="#000000", bg="#FFFFFF")
        lbl_username.place(x=70, y=340)
        lbl_password = Label(self, text="Password", font=Small, bd=5, fg="#000000", bg="#FFFFFF")
        lbl_password.place(x=70, y=395)
        lbl_password1 = Label(self, text="Repeat password", font=Small, bd=5, fg="#000000", bg="#FFFFFF")
        lbl_password1.place(x=70, y=450)
        lbl_result = Label(self, text="", font=Small, fg="#000000", bg="#FFFFFF")
        lbl_result.place(x=70, y=515)
        lbl_login = Label(self, text="Already have an account?", font=Small, fg="#000000", bg="#FFFFFF")
        lbl_login.place(x=120, y=605)
        rfname = Entry(self, font=SmallR, textvariable=RFNAME, width=42)
        rfname.place(x=75, y=200)
        rmname = Entry(self, font=SmallR, textvariable=RMNAME, width=42)
        rmname.place(x=75, y=260)
        rlname = Entry(self, font=SmallR, textvariable=RLNAME, width=42)
        rlname.place(x=75, y=315)
        remail = Entry(self, font=SmallR, textvariable=REMAIL, width=42)
        remail.place(x=75, y=370)
        rpass1 = Entry(self, font=SmallR, textvariable=RPASS, width=42, show="*")
        rpass1.place(x=75, y=425)
        repass1 = Entry(self, font=SmallR, textvariable=REPASS, width=42, show="*")
        repass1.place(x=75, y=480)
        btn_register = Button(self, font=FONT, text="Sign Up", state=NORMAL,
                              command=lambda: register_user(RFNAME.get(), RMNAME.get(), RLNAME.get(), REMAIL.get(),
                                                            RPASS.get(), REPASS.get(), lbl_result, btn_register),
                              fg="#FFFFFF", bg="#30A2FF", height=1, width=20)
        btn_register.place(x=120, y=550)
        button2 = Button(self, font=Small, text="Login", command=lambda: retologin(), fg="#30A2FF",
                         bg="#ffffff", height=1, width=4, borderwidth=0)
        button2.place(x=305, y=602)

        def resetF():
            rfname.delete(0, 'end')
            rmname.delete(0, 'end')
            rlname.delete(0, 'end')
            remail.delete(0, 'end')
            rpass1.delete(0, 'end')
            repass1.delete(0, 'end')
            lbl_result.config(text="")
            btn_register['state'] = NORMAL

        def retologin():
            controller.show_frame(Login)
            resetF()

        def register_user(RFNAME, RMNAME, RLNAME, REMAIL, RPASS, REPASS, lbl_result, btn_register):
            database()
            global current_email
            current_email = REMAIL
            if RFNAME == "" or RMNAME == "" or RLNAME == "" or REMAIL == "" or RPASS == "" or REPASS == "":
                lbl_result.config(text="Please complete the required field!", fg="orange")
            else:
                if RPASS == REPASS:
                    lbl_result.config(text="")
                    queryemail = "SELECT * FROM `users` WHERE email='" + REMAIL + "'"
                    cursor.execute(queryemail)
                    if cursor.fetchone() is not None:
                        lbl_result.config(text="Email is already registered", fg="red")
                    else:
                        RPASS = bcrypt.hashpw(RPASS.encode('utf8'), bcrypt.gensalt())
                        global tempquery
                        tempquery = "INSERT INTO `users` (fname, mname, lname, email, password) VALUES ('"+str(RFNAME)+"', '"+str(RMNAME)+"', '"+str(RLNAME)+"', '"+str(REMAIL)+"', '"+str(RPASS.decode("utf-8"))+"')"
                        print("To be executed: "+tempquery)
                        toActivate()
                else:
                    lbl_result.config(text="Password does not match!", fg="red")

        def toActivate():
            controller.show_frame(RActivation)
            resetF()
            global tempOTP
            tempOTP = random.randint(100000, 999999)
            print("OTP: " + str(tempOTP))
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                msg = EmailMessage()
                msg['Subject'] = 'Registration verification code: ' + str(tempOTP)
                msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                msg['To'] = current_email
                msg.set_content('Use this code to activate your account: ' + str(tempOTP))

                smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

class RActivation(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")

        load = Image.open("assets/otp.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Activation', fg="#ffffFF", bg="#292f36", font=Heading)
        heading.place(x=30,y=20)
        lbl_drotp = Label(self, text="Enter OTP Code sent to your email", font=Small, fg="#FFFFFF", bg="#292f36")
        lbl_drotp.place(x=115, y=300)

        lbl_result = Label(self, text="", font=Small, fg="orange", bg="#292f36")
        lbl_result.place(x=195, y=395)

        encode = StringVar()
        entcode = Entry(self, font=OTP, textvariable=encode, width=22, justify='center')
        entcode.place(x=75, y=350)

        lbl_drotp = Label(self, text="Didn't recieve OTP code?", font=Small, fg="#FFFFFF", bg="#292f36")
        lbl_drotp.place(x=150, y=500)
        sendOTPButton = Button(self, font=Small, text="Resend Code", state=NORMAL, command=lambda: (sendOTP()), fg="#30A2FF", bg="#292f36", borderwidth=0)
        sendOTPButton.place(x=185, y=530)
        buttonset = Button(self, font=FONT, text="< Back", command=lambda: controller.show_frame(Register), fg="#30A2FF", bg="#292f36", borderwidth=0)
        buttonset.place(x=25, y=80)
        buttonproceed = Button(self, font=FONT, text="Verify", command=lambda: verifyOTP(entcode.get(), lbl_result), fg="#FFFFFF", bg="#30A2FF", height=2, width=30, borderwidth=0)
        buttonproceed.place(x=72, y=425)

        def sendOTP():
            global tempOTP
            tempOTP = random.randint(100000, 999999)
            print("OTP: " + str(tempOTP))
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                msg = EmailMessage()
                msg['Subject'] = 'Registration verification code: ' + str(tempOTP)
                msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                msg['To'] = current_email
                msg.set_content('Use this code to activate your account: ' + str(tempOTP))

                smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

        def verifyOTP(encode, lbl_result):
            typedOTP = str(encode)
            print(typedOTP)
            if typedOTP == str(tempOTP):
                controller.show_frame(Login)
                entcode.delete(0, 'end')
                global tempquery
                cursor.execute(tempquery)
                con.commit()
                cursor.close()
                con.close()
                with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                    smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                    msg = EmailMessage()
                    msg['Subject'] = 'Account Registered'
                    msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                    msg['To'] = current_email
                    msg.set_content('Your account has been successfully registered.')
                    smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())
                lbl_result.config(text="")
                tk.messagebox.showinfo(title="SecuroFile", message="Registration Successful")
            else:
                lbl_result.config(text="Invalid OTP", fg="orange")


#main page
class Main(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.configure(bg="#292F36")

        v2=v1.pdf_view(self,pdf_location="", width=95, height=40)
        v2.place(x=480,y=25)

        heading = Label(self, text='SecuroFile', fg="#FFFFFF", bg="#292F36", font=Heading)
        heading.place(x=30,y=20)
        btn_encrypt = Button(self, font=FONT, text="Encrypt", state=NORMAL, command=lambda: (encrypt_file(key)), fg="#FFFFFF", bg="#4ECDC4", borderwidth=0, height=2, width=17)
        btn_encrypt.place(x=30,y=100)
        btn_decrypt = Button(self, font=FONT, text="Open File", state=NORMAL, command=lambda: (decrypt_file()), fg="#FFFFFF", bg="#50C878", borderwidth=0, height=2, width=17)
        btn_decrypt.place(x=250,y=100)
        listbox = Listbox(self, selectmode=MULTIPLE, width=37, height=15, font=('Nirmala UI', 16))
        listbox.place(x=30, y=218)

        lbl_firstname = Label(self, text="Select recipients:", font=Small, bd=5, fg="#ffffff", bg="#292f36")
        lbl_firstname.place(x=25, y=180)

        reButton = Button(self, font=Small, text="Refresh", state=NORMAL, command=lambda: (refresh()),  fg="#30A2FF", bg="#292f36", borderwidth=0)
        reButton.place(x=380, y=180)
        # Using readlines()
        file1 = open('user/contacts.txt', 'r')
        Lines = file1.readlines()

        count = 0
        # Strips the newline character
        for line in Lines:
            count += 1
            listbox.insert(count, line.strip())

        buttoncon = Button(self, font=Small, text="Contacts", command=lambda:controller.show_frame(Contacts), fg="#50C878", bg="#292f36", borderwidth=0)
        buttoncon.place(x=240, y=30)
        buttonset = Button(self, font=Small, text="Devices", command=lambda:verifyDevice(), fg="#30A2FF",bg="#292f36", borderwidth=0)
        buttonset.place(x=320, y=30)
        buttonlogout = Button(self, font=Small, text="Log Out", command=lambda:clearPDF(), fg="#FF6B6B", bg="#292f36", borderwidth=0)
        buttonlogout.place(x=390,y=30)

        def sendtorec(recipients, current_email, fileenc):
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                recipient = []
                for index in recipients:
                    print(index)
                    recipient.append(index)
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                queryable = "SELECT * FROM `users` WHERE email='" + current_email + "'"
                cursor.execute(queryable)
                table = cursor.fetchall()
                name = ''
                for row in table:
                    print(row[1])
                    name = row[1]

                to_email = recipient

                if type(to_email) == str:
                    to_email_str = to_email
                else:
                    to_email_str = ", ".join(to_email)

                msg = EmailMessage()
                msg['Subject'] = name +' sent you an encrypted file'
                msg['From'] = name + ' via SecuroFile'
                msg['To'] = to_email_str
                msg.set_content('Download the attached file and open with SecuroFile')

                epath = Path(fileenc)
                with epath.open("rb") as fp:
                    msg.add_attachment(
                        fp.read(),
                        maintype="plain", subtype="plain",
                        filename=epath.name)

                smtp.sendmail(EMAIL_ADDRESS, recipient, msg.as_string())

        def verifyDevice():
            if isVerified is True:
                controller.show_frame(Device)
            else:
                controller.show_frame(Verification)
                global tempOTP
                tempOTP = random.randint(100000, 999999)
                print("OTP: " + str(tempOTP))
                with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                    smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                    msg = EmailMessage()
                    msg['Subject'] = 'Device verification code: ' + str(tempOTP)
                    msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                    msg['To'] = current_email
                    msg.set_content('Use this code to verify your identity: ' + str(tempOTP))

                    smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

        def clearPDF():
            controller.show_frame(Login)
            v1 = pdf.ShowPdf()
            v1.img_object_li.clear()
            global isVerified
            isVerified = False
            global tempOTP
            tempOTP = 000000
            try:
                os.remove("cache/key")
                os.remove("cache/raw")
                os.remove("cache/recipient")
            except:
                print("Nothing to remove")

        def showPDF(file_name):
            v1 = pdf.ShowPdf()
            v1.img_object_li.clear()
            v1 = pdf.ShowPdf()
            v2 = v1.pdf_view(self, pdf_location=file_name, width=95, height=40, zoomDPI=90)
            v2.place(x=480, y=25)

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

        def mergeenc(directory,file_name):
            with pyzipper.AESZipFile(directory + '/' + file_name + '.enc',
                                     'w',
                                     compression=pyzipper.ZIP_LZMA,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(permakey1)
                for file in list_files:
                    zf.write(file)
            with pyzipper.AESZipFile(directory + '/' + file_name + '.enc') as zf:
                zf.setpassword(permakey1)

        def splitenc(file_path):
            print("Splitting")
            with pyzipper.AESZipFile(file_path, 'r', compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as extracted_zip:
                extracted_zip.extractall(pwd=str.encode(permakey2))

        def getRecipient():
            file1 = open('cache/recipient', 'r')
            Lines = file1.readlines()
            email = []
            for line in Lines:
                email.append(line.strip())
            return email

        def pad(s):
            return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

        def encrypt(message, key):
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
                #fetch selected users
                email = [current_email]
                emailhashed = []
                for index in listbox.curselection():
                    email.insert(index, listbox.get(index))
                    print('Email(s) selected: '+listbox.get(index))
                for index in email:
                    print(index)
                    index = str(bcrypt.hashpw(index.encode('utf8'), bcrypt.gensalt()).decode("utf-8"))
                    print(index)
                    emailhashed.append(str(index))
                for index in emailhashed:
                    print(index)
                with open('cache/recipient', 'w') as f:
                    for line in emailhashed:
                        f.write(line)
                        f.write('\n')
                print("Email(s) submitted")

                #summary of file selected
                file_path = filedialog.askopenfilename()
                head, tail = os.path.split(file_path)
                root, ext = os.path.splitext(tail)
                print("File Name: " + str(tail))
                print("File Directory: " + str(head))
                print("File Path: " + str(file_path))
                fileenc = file_path.replace(ext, '.enc')
                print("Encrypted File Path: " + fileenc)
                #encryption process
                with open(file_path, 'rb') as fo:
                    plaintext1 = fo.read()
                enc = encrypt(plaintext1, key)
                with open("cache/enc", 'wb') as fo:
                    fo.write(enc)
                mergeenc(head,root)
                print("Succesfully Encrypted!")
                sendtorec(email, current_email, fileenc)
                tk.messagebox.showinfo(title="SecuroFile", message="Successfully Encrypted!")
            except Exception:
                traceback.print_exc()

        def decrypt_file():
            try:
                #summary of file selected
                file_path = filedialog.askopenfilename()
                head, tail = os.path.split(file_path)
                print("File Name: " + str(tail))
                print("File Directory: " + str(head))
                print("File Path: " + str(file_path))
                print(file_path)
                #decryption process
                splitenc(file_path)
                isDecrypted = False
                emailmatch = False
                devicematch = False
                for x in getRecipient():
                    if bcrypt.checkpw(current_email.encode(), x.encode()):
                        emailmatch = True
                        database()
                        queryable = "SELECT deviceID FROM `user_devices` WHERE email = '" + current_email + "'"
                        cursor.execute(queryable)
                        table = cursor.fetchall()
                        for row in table:
                            if row[0] == getHardwareId():
                                devicematch = True
                                with open("cache/enc", 'rb') as fo1:
                                    ciphertext = fo1.read()
                                with open("cache/key", 'rb') as fo2:
                                    fkey = fo2.read()
                                    print("Key: " + str(fkey))
                                dec = decrypt(ciphertext, fkey)
                                with open("cache/raw", 'wb') as fo:
                                    fo.write(dec)
                                isDecrypted = True
                                showPDF("cache/raw")
                if isDecrypted:
                    for file in list_files:
                        os.remove(file)
                    gennewkey()
                    print("Succesfully Decrypted!")
                    tk.messagebox.showinfo(title="SecuroFile", message="Succesfully Decrypted!")
                else:
                    if not emailmatch and not devicematch:
                        print("You are not authorized to open this file.")
                        tk.messagebox.showinfo(title="Access Denied!", message="You are not authorized to open this file.")
                    elif emailmatch and not devicematch:
                        print("Please make sure to use your registered device in opening this file.")
                        tk.messagebox.showinfo(title="Access Denied!", message="Please make sure to use your registered device in opening this file.")
            except Exception:
                traceback.print_exc()

class Contacts(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.configure(bg="#292F36")

        load = Image.open("assets/contacts.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Contacts', fg="#FFFFFF", bg="#292F36", font=Heading)
        heading.place(x=30,y=20)

        impButton = Button(self, font=Small, text="Import Contacts", state=NORMAL, command=lambda: (importContact()), fg="#30A2FF", bg="#292f36", borderwidth=0)
        impButton.place(x=320, y=30)

        buttonset = Button(self, font=FONT, text="< Back", command=lambda: controller.show_frame(Main), fg="#30A2FF", bg="#292f36", borderwidth=0)
        buttonset.place(x=25, y=80)

        reButton = Button(self, font=Small, text="Refresh", state=NORMAL, command=lambda: (refresh()),  fg="#30A2FF", bg="#292f36", borderwidth=0)
        reButton.place(x=380, y=195)

        listbox = Listbox(self, selectmode=MULTIPLE, width=37, height=13, font=('Nirmala UI', 16))
        listbox.place(x=30, y=230)
        entrybox = Entry(self, width=23, font=('Nirmala UI', 20))
        entrybox.place(x=30, y=140)
        addButton = Button(self, font=FONT, text="Add", state=NORMAL, command=lambda: (add()), bg="#50C878", fg="#FFFFFF", borderwidth=0)
        addButton.place(x=390, y=140)

        delButton = Button(self, font=FONT, text="Remove Selected", state=NORMAL, command=lambda: (delete()), fg="#FFFFFF", bg="#FF6B6B", borderwidth=0)
        delButton.place(x=30, y=650)

        # Using readlines()
        file1 = open('user/contacts.txt', 'r')
        Lines = file1.readlines()

        count = 0
        # Strips the newline character
        for line in Lines:
            count += 1
            listbox.insert(count, line.strip())

        def add():
            if re.fullmatch(regex, entrybox.get()):
                listbox.insert(listbox.size(), entrybox.get())

                all_items = listbox.get(0, tk.END)

                with open('user/contacts.txt', 'w') as f:
                    for line in all_items:
                        f.write(line)
                        f.write('\n')

                print("Email added")
                entrybox.delete(0, 'end')
                tk.messagebox.showinfo(title="SecuroFile", message="Email added.")
            else:
                print("Invalid Email")
                tk.messagebox.showinfo(title="SecuroFile", message="Invalid Email.")

        def importContact():
            file_path = filedialog.askopenfilename()
            head, tail = os.path.split(file_path)
            print("File Name: " + str(tail))
            print("File Directory: " + str(head))
            print("File Path: " + str(file_path))
            with open(file_path, 'rb') as fo:
                contacts = fo.read()
            with open('user/contacts.txt', 'wb') as fo:
                fo.write(contacts)
            file = open('user/contacts.txt', 'r')
            Lines = file.readlines()
            count = 0
            listbox.delete(0, tk.END)
            for line in Lines:
                count += 1
                listbox.insert(count, line.strip())

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

class Verification(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")

        load = Image.open("assets/otp.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Verification', fg="#ffffFF", bg="#292f36", font=Heading)
        heading.place(x=30,y=20)
        lbl_drotp = Label(self, text="Enter OTP Code sent to your email", font=Small, fg="#FFFFFF", bg="#292f36")
        lbl_drotp.place(x=115, y=300)

        lbl_result = Label(self, text="", font=Small, fg="orange", bg="#292f36")
        lbl_result.place(x=195, y=395)

        encode = StringVar()
        entcode = Entry(self, font=OTP, textvariable=encode, width=22, justify='center')
        entcode.place(x=75, y=350)

        lbl_drotp = Label(self, text="Didn't recieve OTP code?", font=Small, fg="#FFFFFF", bg="#292f36")
        lbl_drotp.place(x=150, y=500)
        sendOTPButton = Button(self, font=Small, text="Resend Code", state=NORMAL, command=lambda: (sendOTP()), fg="#30A2FF", bg="#292f36", borderwidth=0)
        sendOTPButton.place(x=185, y=530)
        buttonset = Button(self, font=FONT, text="< Back", command=lambda: controller.show_frame(Main), fg="#30A2FF", bg="#292f36", borderwidth=0)
        buttonset.place(x=25, y=80)
        buttonproceed = Button(self, font=FONT, text="Verify", command=lambda: verifyOTP(entcode.get(), lbl_result), fg="#FFFFFF", bg="#30A2FF", height=2, width=30, borderwidth=0)
        buttonproceed.place(x=72, y=425)

        def sendOTP():
            global tempOTP
            tempOTP = random.randint(100000, 999999)
            print("OTP: " + str(tempOTP))
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                msg = EmailMessage()
                msg['Subject'] = 'Device verification code: ' + str(tempOTP)
                msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                msg['To'] = current_email
                msg.set_content('Use this code to verify your identity: ' + str(tempOTP))

                smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

        def verifyOTP(encode, lbl_result):
            typedOTP = str(encode)
            print(typedOTP)
            if typedOTP == str(tempOTP):
                controller.show_frame(Device)
                entcode.delete(0, 'end')
                global isVerified
                isVerified = True
            else:
                lbl_result.config(text="Invalid OTP", fg="orange")


class Device(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")

        load = Image.open("assets/devices.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Device List', fg="#FFFFFF", bg="#292F36", font=Heading)
        heading.place(x=30,y=20)
        heading1 = Label(self, text="Current Device: " + getHardwareId(), fg="#FFFFFF", bg="#292F36", font=('Nirmala UI', 9, 'bold'))
        heading1.place(x=30,y=130)
        listbox = Listbox(self, width=68, height=25)
        listbox.place(x=30, y=230)
        listbox.insert(0, "Refresh to Reveal Devices")
        reButton = Button(self, font=Small, text="Refresh", state=NORMAL, command=lambda: (refresh()), fg="#30A2FF", bg="#292f36", borderwidth=0)
        reButton.place(x=380, y=195)
        addButton = Button(self, font=FONT, text="Register Device", state=NORMAL,command=lambda: (regdev(getHardwareId())),bg="#50C878", fg="#FFFFFF", borderwidth=0)
        addButton.place(x=30, y=175)
        delButton = Button(self, font=FONT, text="Remove Selected", state=NORMAL, command=lambda: (delete()), fg="#FFFFFF", bg="#FF6B6B", borderwidth=0)
        delButton.place(x=30, y=650)
        buttonset = Button(self, font=FONT, text="< Back", command=lambda: controller.show_frame(Main), fg="#30A2FF", bg="#292f36", borderwidth=0)
        buttonset.place(x=25, y=80)

        def refresh():
            listbox.delete(0, tk.END)
            print("Start Get Devices")
            database()
            global current_email
            queryable = "SELECT deviceID FROM `user_devices` WHERE email = '" + current_email + "'"
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
                with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                    smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                    msg = EmailMessage()
                    msg['Subject'] = 'A device has been removed'
                    msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                    msg['To'] = current_email
                    msg.set_content('Device: ' + devstr + ' has been removed from your account.')
                    smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())
            except:
                print("Something went wrong")
                tk.messagebox.showinfo(title="SecuroFile", message="No device selected.")

        def regdev(current_machine_id):
            database()
            print("Current Device ID: " + str(current_machine_id))
            query = "select * from devices WHERE user_id = '"+str(user_id)+"'"
            query2 = "SELECT COUNT(email) FROM `user_devices` WHERE email = '"+current_email+"'"
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
                    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                        smtp.ehlo()
                        smtp.starttls()
                        smtp.ehlo()
                        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                        msg = EmailMessage()
                        msg['Subject'] = 'A device has been added'
                        msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                        msg['To'] = current_email
                        msg.set_content('Device: ' + current_machine_id + ' has been added to your account.')
                        smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())
            else:
                print("Maximum devices allocated.")
                tk.messagebox.showinfo(title="SecuroFile", message="Maximum devices allocated.")

class AskEmail(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.configure(bg="#27374D")

        load = Image.open("assets/bg.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        heading = Label(self, text='Forgot your password?', fg="#FFFFFF", bg=BGCOL, font=Heading2)
        heading.place(x=50, y=100)

        lbl_login = Label(self, text="We'll send a code to your email to verify the account.", font=SmallR, fg="#FFFFFF", bg=BGCOL)
        lbl_login.place(x=50, y=150)

        EMAIL = StringVar()

        lbl_username = Label(self, text="Your email", font=FONT, bd=10, fg="#FFFFFF", bg=BGCOL)
        lbl_username.place(x=40, y=200)
        email = Entry(self, font=FONTR, textvariable=EMAIL, width=36)
        email.place(x=50, y=250)
        lbl_result = Label(self, text="", font=Small, fg="#FFFFFF", bg=BGCOL)
        lbl_result.place(x=50, y=290)

        btn_login = Button(self, font=FONT, text="Send Code",
                           command=lambda: rescodeemail(EMAIL.get(), lbl_result), fg="#FFFFFF", bg="#30A2FF",
                           height=1, width=20)
        btn_login.place(x=120, y=340)

        button2 = Button(self, font=Small, text="Back to Login",
                         command=lambda: controller.show_frame(Login), fg="#30A2FF",
                         bg="#27374D", height=1, width=20, borderwidth=0)
        button2.place(x=140, y=400)

        def rescodeemail(EMAIL, lbl_result):
            database()
            print("Email: " + str(EMAIL))
            hashed = ""
            if EMAIL == "":
                lbl_result.config(text="Please complete the required field!", fg="orange")
            else:
                global current_email
                current_email = EMAIL
                queryable = "SELECT * FROM `users` WHERE email='" + EMAIL + "'"
                cursor.execute(queryable)
                if cursor.fetchone() is not None:
                    controller.show_frame(Verification2)
                    global tempOTP
                    tempOTP = random.randint(100000, 999999)
                    print("OTP: " + str(tempOTP))
                    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                        smtp.ehlo()
                        smtp.starttls()
                        smtp.ehlo()
                        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                        msg = EmailMessage()
                        msg['Subject'] = 'Reset Password verification code: ' + str(tempOTP)
                        msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                        msg['To'] = EMAIL
                        msg.set_content('Use this code to verify your identity: ' + str(tempOTP))

                        smtp.sendmail(EMAIL_ADDRESS, EMAIL, msg.as_string())
                    email.delete(0, 'end')

class Verification2(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="#292F36")

        load = Image.open("assets/otp.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        lbl_drotp = Label(self, text="Enter OTP Code sent to your email", font=Small, fg="#FFFFFF", bg="#292f36")
        lbl_drotp.place(x=115, y=300)

        lbl_result = Label(self, text="", font=Small, fg="orange", bg="#292f36")
        lbl_result.place(x=195, y=395)

        encode = StringVar()
        entcode = Entry(self, font=OTP, textvariable=encode, width=22, justify='center')
        entcode.place(x=75, y=350)

        lbl_drotp = Label(self, text="Didn't recieve OTP code?", font=Small, fg="#FFFFFF", bg="#292f36")
        lbl_drotp.place(x=150, y=500)
        sendOTPButton = Button(self, font=Small, text="Resend Code", state=NORMAL, command=lambda: (sendOTP()),
                               fg="#30A2FF", bg="#292f36", borderwidth=0)
        sendOTPButton.place(x=185, y=530)

        buttonset = Button(self, font=FONT, text="Cancel", command=lambda: controller.show_frame(Login), fg="#FF2400", bg="#292f36", borderwidth=0)
        buttonset.place(x=25, y=20)

        buttonproceed = Button(self, font=FONT, text="Verify", command=lambda: verifyOTP(entcode.get(), lbl_result), fg="#FFFFFF", bg="#30A2FF", height=2, width=30, borderwidth=0)
        buttonproceed.place(x=72, y=425)

        def sendOTP():
            global tempOTP
            tempOTP = random.randint(100000, 999999)
            print("OTP: " + str(tempOTP))
            with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                msg = EmailMessage()
                msg['Subject'] = 'Device verification code: ' + str(tempOTP)
                msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                msg['To'] = current_email
                msg.set_content('Use this code to verify your identity: ' + str(tempOTP))

                smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

        def verifyOTP(encode, lbl_result):
            typedOTP = str(encode)
            print(typedOTP)
            if typedOTP == str(tempOTP):
                controller.show_frame(ResetPassword)
                entcode.delete(0, 'end')
            else:
                lbl_result.config(text="Invalid OTP", fg="orange")

class ResetPassword(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.configure(bg="#27374D")

        load = Image.open("assets/bg.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0)
        img.image = render
        img.place(x=0, y=0)

        buttonset = Button(self, font=FONT, text="Cancel", command=lambda: controller.show_frame(Login), fg="#FF2400",
                           bg=BGCOL, borderwidth=0)
        buttonset.place(x=25, y=20)

        heading = Label(self, text='Reset account password', fg="#FFFFFF", bg=BGCOL, font=Heading2)
        heading.place(x=50, y=100)

        lbl_login = Label(self, text="Enter a new password.", font=SmallR,
                          fg="#FFFFFF", bg=BGCOL)
        lbl_login.place(x=50, y=150)

        pass1 = StringVar()
        pass2 = StringVar()

        pass1L = Label(self, text="New password", font=FONT, bd=10, fg="#FFFFFF", bg=BGCOL)
        pass1L.place(x=40, y=200)
        pasS1 = Entry(self, font=FONTR, textvariable=pass1, width=36, show="*")
        pasS1.place(x=50, y=250)

        pass2L = Label(self, text="Confirm password", font=FONT, bd=10, fg="#FFFFFF", bg=BGCOL)
        pass2L.place(x=40, y=280)
        pasS2 = Entry(self, font=FONTR, textvariable=pass2, width=36, show="*")
        pasS2.place(x=50, y=330)

        lbl_result = Label(self, text="", font=Small, fg="#FFFFFF", bg=BGCOL)
        lbl_result.place(x=50, y=370)

        btn_login = Button(self, font=FONT, text="Reset Password",
                           command=lambda: respas(pass1.get(), pass2.get(), lbl_result), fg="#FFFFFF", bg="#30A2FF",
                           height=1, width=20)
        btn_login.place(x=120, y=410)

        def respas(pass1, pass2, lbl_result):
            database()
            print("pass1: " + str(pass1))
            print("pass2: " + str(pass2))
            if pass1 != pass2:
                lbl_result.config(text="Password does not match", fg="orange")
            else:
                controller.show_frame(Login)
                global current_email
                PASS = bcrypt.hashpw(pass2.encode('utf8'), bcrypt.gensalt())
                cursor.execute(
                    "UPDATE `users` SET password = '"+(str(PASS.decode("utf-8")))+"' WHERE email ='"+(str(current_email))+"'")
                lbl_result.config(text="", fg="green")
                con.commit()
                cursor.close()
                con.close()
                pasS1.delete(0, 'end')
                pasS2.delete(0, 'end')

                with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                    smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                    msg = EmailMessage()
                    msg['Subject'] = 'Reset Account Password'
                    msg['From'] = 'SecuroFile <' + EMAIL_ADDRESS + '>'
                    msg['To'] = current_email
                    msg.set_content('Your password has been changed successfully.')
                    smtp.sendmail(EMAIL_ADDRESS, current_email, msg.as_string())

                tk.messagebox.showinfo(title="SecuroFile", message="Password changed successfully!")

#start app code
app = SecuroFileApp()
def callback():
    if messagebox.askokcancel("Quit", "Do you really wish to quit?"):
        app.destroy()
        print("Listener Stop")
        listener1.stop()

app.protocol("WM_DELETE_WINDOW", callback)
app.iconbitmap("icon.ico")
app.mainloop()
try:
    listener1.join()
except:
    print("Process halted")
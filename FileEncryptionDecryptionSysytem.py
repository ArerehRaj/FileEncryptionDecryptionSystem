from tkinter import *
import os
import MySQLdb
from tkinter import filedialog
from PyPDF2 import PdfFileWriter, PdfFileReader
import MySQLdb
from cryptography.fernet import Fernet

global loggedInUsername

myConnection = MySQLdb.connect(host='localhost', database='FileHandling', user='root', password='RjRathod@2002')
cursor = myConnection.cursor()

# Created the Database named File Handling
# cursor.execute('create database FileHandling')

# Created Table named UserDetails for storing their username, password and PIN in DB
# cursor.execute('create table UserDetails(Usernames varchar(25), Password varchar(25), PIN int)')

# Setting the tuple for respective Font style
Font_tuple = ("Comic Sans MS", 15, "bold")

# Designing window for registration
def create_window(loggedInUsername):
    global window
    window = Tk()
    window.title("File Encryption System")
    window.configure(bg="floral white")
    window.iconbitmap(r"D:\PYTHON\OSPTL\MINI_PROJECT\lock.ico")
    window.geometry("1000x1000")
    mess = 'Welcome', loggedInUsername
    w = Label(window, text=mess, bg="floral white", font=("Comic Sans MS",40,"bold"))
    w.grid(row=0, columnspan=2)

    myfile_img = PhotoImage(file=r"D:\PYTHON\OSPTL\MINI_PROJECT\folderFinal.png")

    myfile_but = Button(window, text='MY FILES', bg="floral white", image=myfile_img,borderwidth=0, font=("Comic Sans MS",30,"bold"), compound=TOP, command=myFiles)
    myfile_but.grid(row=1, column=0)

    my_label = Label(window, font=Font_tuple, text='', bg="floral white")
    my_label.grid(row=2, column=0)

    efile_but = Button(window, bg="floral white", font=("Comic Sans MS",30,"bold"), text='ENCRYPTED FILES',image=myfile_img, borderwidth=0, compound=TOP, command=lambda: encryptedFiles(loggedInUsername))
    efile_but.grid(row=1, column=1)

    my_label = Label(window, font=Font_tuple, text='', bg="floral white")
    my_label.grid(row=2, column=1)

    frame1 = Frame(window, bg="floral white",)
    frame1.grid(row=3, columnspan=2)

    plus1_img = PhotoImage(
        file=r"D:\PYTHON\OSPTL\MINI_PROJECT\plusFinal.png")

    plus_but = Button(frame1, bg="floral white", image=plus1_img, command=lambda:[EnterPin(loggedInUsername, 'Encrypt')], borderwidth=0)
    plus_but.pack(side=LEFT, padx=(0, 30))

    plus_label = Label(frame1, text='Add file to be encrypted',bg="floral white", font=("Comic Sans MS",30,"bold"))
    plus_label.pack(side=LEFT)

    frame2 = Frame(window, bg="floral white")
    frame2.grid(row=4, columnspan=2)

    unlock_img = PhotoImage(file=r"D:\PYTHON\OSPTL\MINI_PROJECT\unlockFinal.png")

    unlock_but = Button(frame2, bg="floral white", image=unlock_img, command=lambda: [decryptedFiles(loggedInUsername)], borderwidth=0)
    unlock_but.pack(padx=(0, 30), side=LEFT)

    unlock_label = Label(frame2, font=("Comic Sans MS",30,"bold"),bg="floral white", text='Decrypt the encrypted files')
    unlock_label.pack(side=LEFT)

    logout_but = Button(window, bg="gray17", fg="white", font=Font_tuple, text='LOGOUT',borderwidth=10, command=lambda: [delete_window(), main_account_screen()])
    logout_but.grid(row=5,pady=(0,10), columnspan=2)

    window.columnconfigure(0, weight=1)
    window.columnconfigure(1, weight=1)

    window.rowconfigure(0, weight=2)
    window.rowconfigure(1, weight=0)
    window.rowconfigure(2, weight=1)
    window.rowconfigure(3, weight=1)
    window.rowconfigure(4, weight=2)

    window.mainloop()

# Function for opening file from the application
def myFiles():
    window.filename = filedialog.askopenfilename(initialdir='/', title="Select A File", filetype=(('pdf', '*.pdf'), ('docx', '*.docx'), ('csv', '*.csv'), ('png', '*.png'), ('jpg', '*.jpg'), ('jpeg', '*.jpeg'), ('All Files', '*.*')))
    os.startfile(window.filename)

# Function for opening and checking for encrypted files
def openFiles(filepath):
    os.startfile(filepath)


if False:
    key = Fernet.generate_key()
    with open('filekey.key', 'wb') as filekey:
        filekey.write(key)

# myConnection = MySQLdb.connect(host='localhost', database='FileHandling', user='root', password='MekoNahiPata21@')
# cursor = myConnection.cursor()

def thing():
    pass

# Function for encrypting the file choosen by the user
def openFile(loggedInUsername, pinValue):
    # Getting the file path for the selected file
    window.filename = filedialog.askopenfilename(initialdir='/', title="Select A File", filetype=(('pdf', '*.pdf'), ('docx', '*.docx'), ('csv', '*.csv'), ('png', '*.png'), ('jpg', '*.jpg'), ('jpeg', '*.jpeg'), ('All Files', '*.*')))
    
    # Checking if the file selected is PDF
    if window.filename.endswith('.pdf'):

        # Encryption logic for PDF file
        out = PdfFileWriter()
        file = PdfFileReader(window.filename)
        num = file.numPages

        # SQL query for storing the file in DB
        sql_insert_blob_query = """insert into UserFiles(Usernames, filePath, IsEncrypted, File, FileKey ) VALUES (%s,%s,%s,%s,%s)"""

        chosedFile = convertToBinaryData(window.filename)
        fileKey = "NOT_REQUIRED"
        newFile = (loggedInUsername, window.filename,"True", chosedFile, fileKey)
        cursor.execute(sql_insert_blob_query, newFile)
        myConnection.commit()

        for i in range(num):
            page = file.getPage(i)
            out.addPage(page)

        # storing the password of PDF file as the Users PIN
        password = str(pinValue)
        out.encrypt(password)
        with open(window.filename, "wb") as f:
            out.write(f)

    # Checking if the file selected is DOC
    elif window.filename.endswith('.docx'):

        # Encryption logic for DOC file
        with open('filekey.key', 'rb') as filekey:
            key = filekey.read()

        # SQL query for storing the file in DB
        sql_insert_blob_query = """insert into UserFiles(Usernames, filePath, IsEncrypted, File, FileKey ) VALUES (%s,%s,%s,%s,%s)"""
        chosedFile = convertToBinaryData(window.filename)
        fileKey = str(key)
        newFile = (loggedInUsername, window.filename,
                   "True", chosedFile, fileKey)
        cursor.execute(sql_insert_blob_query, newFile)
        myConnection.commit()

        # Setting up the fernet key for encrypting the file
        fernet = Fernet(key)
        with open(window.filename, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(window.filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

    # Checking if the file selected is CSV
    elif window.filename.endswith('.xlsx') or window.filename.endswith('.csv') or window.filename.endswith('.xls'):
        
        # Encryption logic for CSV file
        with open('filekey.key', 'rb') as filekey:
            key = filekey.read()

        # SQL query for storing the file in DB
        sql_insert_blob_query = """insert into UserFiles(Usernames, filePath, IsEncrypted, File, FileKey ) VALUES (%s,%s,%s,%s,%s)"""
        chosedFile = convertToBinaryData(window.filename)
        fileKey = str(key)
        newFile = (loggedInUsername, window.filename,
                   "True", chosedFile, fileKey)
        cursor.execute(sql_insert_blob_query, newFile)
        myConnection.commit()

        # Setting up the fernet key for encrypting the file
        fernet = Fernet(key)
        with open(window.filename, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(window.filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

    # Checking if the file selected is Image
    elif window.filename.endswith('.png') or window.filename.endswith('.jpg') or window.filename.endswith('.jpeg'):
        
        # Encryption logic for Image files including JPG or PNG or JPEG
         # SQL query for storing the file in DB
        sql_insert_blob_query = """insert into UserFiles(Usernames, filePath, IsEncrypted, File, FileKey ) VALUES (%s,%s,%s,%s,%s)"""
        chosedFile = convertToBinaryData(window.filename)
        fileKey = 22
        newFile = (loggedInUsername, window.filename,
                   "True", chosedFile, fileKey)
        cursor.execute(sql_insert_blob_query, newFile)
        myConnection.commit()

        fin = open(window.filename, 'rb')
        image = fin.read()
        fin.close()
        image = bytearray(image)
        key = fileKey
        for index, values in enumerate(image):
            image[index] = values ^ key
        fin = open(window.filename, 'wb')
        fin.write(image)
        fin.close()

# Function to convert our files into binary data for storing the files in DB
def convertToBinaryData(filename):
    # Convert digital data to binary format
    with open(filename, 'rb') as file:
        binaryData = file.read()
    return binaryData

# Function to decrypt the files using filePath and PIN of the user
def decryptFile(filePath, pinValue):

    # Opening the fernet key for decryption process
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()
    
    # Checking if the file is PDF
    if filePath.endswith('.pdf'):
        # Decryption process for PDF files
        out = PdfFileWriter()
        file = PdfFileReader(filePath)
        password = str(pinValue)
        # Checking if the file is Encrypted or not
        # if encrypted then decrypt the file or the file is already decrypted
        if file.isEncrypted:
            file.decrypt(password) # Decrypting the file using PIN of the user as password of the PDF file 
            for idx in range(file.numPages):
                page = file.getPage(idx)
                out.addPage(page)
            with open(filePath, "wb") as f:
                out.write(f)
            print("File decrypted Successfully.")
        else:
            print("File already decrypted.")
        
    # Decryption process for Image files
    elif filePath.endswith('.png') or filePath.endswith('.jpg') or filePath.endswith('.jpeg'):
        # Opening the image files using their path in read binary mode
        fin = open(filePath, 'rb')
        image = fin.read()
        fin.close()
        image = bytearray(image) # Getting the byte array of the image
        newKey = 22 # Set the key value to 22 because the range is 0 to 256 or else it will raise error
        for index, values in enumerate(image):
            image[index] = values ^ newKey # XOR operation performed for decryption
        fin = open(filePath, 'wb')
        fin.write(image)
        fin.close()
        print('Decryption Done Image...')

    # Decryption process for CSV files
    elif window.filename.endswith('.xlsx') or window.filename.endswith('.csv') or window.filename.endswith('.xls'):
        fernet = Fernet(key) # Reading the fernet key
        with open(filePath, 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted) # Decrpteing the encrypted CSV file
        with open(filePath, 'wb') as dec_file:
            dec_file.write(decrypted)
        
    # Decryption process for DOC files
    elif filePath.endswith('.docx'):
        fernet = Fernet(key) # Reading the fernet key
        with open(filePath, 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted) # Decrpteing the encrypted DOC file
        with open(filePath, 'wb') as dec_file:
            dec_file.write(decrypted)
        
    # SQL query to delete the record of respective file which was encrypted from the DB
    stringCommand = "DELETE FROM UserFiles WHERE FilePath='%s'"
    args = (filePath,)
    cursor.execute(stringCommand % args)
    myConnection.commit()

# Function to Destroy or close the PIN screen or window
def Delete_Enter_Pin(loggedInUsername):
    pin_screen.destroy()

# Function to verify the PIN provided by the User
def pinVerification(loggedInUsername, flagValue, filePath=None):
    
    # SQL query for selecting rows having username provided by the user
    str = "SELECT Usernames,Password,PIN FROM UserDetails where Usernames='%s'"
    args = (loggedInUsername,)
    cursor.execute(str % args)
    row = cursor.fetchone() # Fetching the row from the executed SQL query
    # print(pin.get())
    # print(type(pin.get()))
    pinValue = int(pin.get()) # Getting the PIN of the user
    # print(pin.get())
    # print(type(pin.get()))
    pin.set("")
    # print('PIN VALUE', pinValue)

    # Checking if the PIN provided by the user matches with the PIN stored in DB
    if pinValue == row[2]: 
        Delete_Enter_Pin(loggedInUsername) # Function to destory the PIN Window
        if flagValue == 'Encrypt': # Checking the flag for Encryption of the file
            openFile(loggedInUsername, pinValue)
        elif flagValue == 'Decrypt': # Checking the flag for Decryption of the file
            # print('Decrpty')
            # print(filePath)
            decryptFile(filePath, pinValue)
            delete_dwindow()

    else: # Meaning invalid PIN provided by the user
        pin_lable = Label(pin_screen, text="Invalid PIN")
        pin_lable.pack()

# Function to Take the PIN of the user as INPUT
def EnterPin(loggedInUsername, flagValue, filePath=None):
    # SQL query to get the user details based on their username
    str = "SELECT Usernames,Password,PIN FROM UserDetails where Usernames='%s'"
    args = (loggedInUsername,)
    cursor.execute(str % args)
    row = cursor.fetchone()

    global pin_screen
    global pin_entry
    global pin

    pin = StringVar()
    pin_screen = Toplevel(window)
    pin_screen.configure(bg="floral white")
    pin_lable = Label(pin_screen, bg="floral white",text="Please Enter You PIN *", font=Font_tuple)
    pin_lable.pack()
    pin_entry = Entry(pin_screen, textvariable=pin, show="*")
    # print(pin)
    # print(pin_entry.get())
    pin_entry.pack()
    # Button to check the PIN if the PIN is right or not 
    Button(pin_screen, bg="gray17", fg="white", text="ENTER", font=Font_tuple,command=lambda: [pinVerification(loggedInUsername, flagValue, filePath)]).pack() 


myConnection = MySQLdb.connect(host='localhost', database='FileHandling', user='root', password='RjRathod@2002')
cursor = myConnection.cursor()

# cursor.execute('create table UserFiles(Usernames varchar(25), FilePath varchar(300), IsEncrypted varchar(10), File LONGBLOB, FileKey varchar(100))')
# cursor.execute('create table UserFiless(Usernames varchar(25), FilePath varchar(300), IsEncrypted varchar(10), File LONGBLOB,FileKey varchar(300))')

# Function to show the encrypted files of the USER
def encryptedFiles(loggedInUsername):
    global ewindow
    ewindow = Toplevel(window)
    ewindow.title('Encrypted Files')
    ewindow.geometry("1000x1000")
    ewindow.configure(bg="floral white")

    # SQL query to get the user file rows of the user using username
    str = "SELECT FilePath FROM UserFiles where Usernames='%s'"
    args = (loggedInUsername,)
    cursor.execute(str % args)
    rows = cursor.fetchall()
    # print(cursor.rowcount)
    Label(ewindow, bg="floral white", text="File Path",
          width=50, font=Font_tuple).grid(row=0, column=0)
    Label(ewindow, bg="floral white", text="File Name",
          width=30, font=Font_tuple).grid(row=0, column=1)
    Label(ewindow, bg="floral white", text="File Extension",
          width=15, font=Font_tuple).grid(row=0, column=2)

    r = 1

    # Iterating over each row having files or File objects
    for row in rows:
        fileType = row[0].split('.')[-1]
        fileName = row[0].split('/')[-1]
        Label(ewindow, bg="floral white",
              text=row[0], width=50, font=Font_tuple).grid(row=r, column=0)
        Label(ewindow, bg="floral white", text=fileName,
              width=30, font=Font_tuple).grid(row=r, column=1)
        Label(ewindow,padx=5, bg="floral white", text=fileType,
              width=15, font=Font_tuple).grid(row=r, column=2)
        Button(ewindow,padx=5, bg="gray17", fg="white", text="Open", width=10, font=Font_tuple,
               command=lambda x=row[0]: [openFiles(x)]).grid(row=r, column=3)

        r = r+1

    ewindow.columnconfigure(0, weight=4)
    ewindow.columnconfigure(1, weight=4)
    ewindow.columnconfigure(2, weight=1)
    ewindow.columnconfigure(3, weight=1)

# Function to show the encrypted files to Decrypte the files based on user choice
def decryptedFiles(loggedInUsername):
    global dwindow
    dwindow = Toplevel(window)
    dwindow.title('Decrypted Files')
    dwindow.geometry("1000x1000")
    dwindow.configure(bg="floral white")
    # SQL query to get the file rows from the UserFiless table based on username
    str = "SELECT FilePath FROM UserFiles where Usernames='%s'"
    args = (loggedInUsername,)
    cursor.execute(str % args)
    rows = cursor.fetchall()
    # print(cursor.rowcount)
    Label(dwindow, bg="floral white", text="File Path",
          font=Font_tuple).grid(row=0, column=0)
    Label(dwindow, bg="floral white", text="File Name",
          font=Font_tuple).grid(row=0, column=1)
    Label(dwindow, bg="floral white", text="File Extension",
          font=Font_tuple).grid(row=0, column=2)

    r = 1

    # Iterating over all the rows of the files
    for row in rows:
        fileType = row[0].split('.')[-1]
        fileName = row[0].split('/')[-1]
        Label(dwindow, bg="floral white",
              text=row[0], font=Font_tuple, width=50).grid(row=r, column=0)
        Label(dwindow, bg="floral white", text=fileName,
              width=30, font=Font_tuple).grid(row=r, column=1)
        Label(dwindow, bg="floral white", padx=5, text=fileType,
              width=15, font=Font_tuple).grid(row=r, column=2)
        Button(dwindow, bg="gray17", fg="white", padx=5, text="Decrypt", font=Font_tuple, width=15,
               command=lambda x=loggedInUsername, y='Decrypt', z=row[0]: [EnterPin(x, y, z)]).grid(row=r, column=3)
        r = r+1
    dwindow.columnconfigure(0, weight=4)
    dwindow.columnconfigure(1, weight=4)
    dwindow.columnconfigure(2, weight=1)
    dwindow.columnconfigure(3, weight=1)

# Functions for deleting the respective windows
def delete_window():
    window.destroy()


def delete_dwindow():
    dwindow.destroy()

# Function to open up a window where a new user can register
def register():
    global register_screen
    register_screen = Toplevel(main_screen)
    register_screen.title("Register")
    register_screen.geometry("400x400")
    register_screen.configure(bg="floral white")

    global username
    global password
    global pin
    global username_entry
    global password_entry
    global pin_entry
    username = StringVar()
    password = StringVar()
    pin = StringVar()

    Label(register_screen, text="Please enter details below",
          bg="floral white", font=Font_tuple).pack()
    Label(register_screen, bg="floral white", text="").pack()
    username_lable = Label(register_screen, bg="floral white",
                           text="Username * ", font=Font_tuple)
    username_lable.pack()
    username_entry = Entry(
        register_screen, textvariable=username, font=Font_tuple)
    username_entry.pack()
    password_lable = Label(register_screen, bg="floral white",
                           text="Password * ", font=Font_tuple)
    password_lable.pack()
    password_entry = Entry(
        register_screen, textvariable=password, show='*', font=Font_tuple)
    password_entry.pack()
    pin_lable = Label(register_screen, bg="floral white",
                      text="PIN * ", font=Font_tuple)
    pin_lable.pack()
    pin_entry = Entry(register_screen, textvariable=pin,
                      show='*', font=Font_tuple)
    pin_entry.pack()
    Label(register_screen, bg="floral white", text="").pack()
    # Button which when clicked calls the register user function for storing the data in DB
    Button(register_screen, bg="gray17",fg='white', text="Register", width=10,
           height=1, font=Font_tuple, command=register_user).pack()


# Designing window for login
def login():
    global login_screen
    login_screen = Toplevel(main_screen)
    login_screen.title("Login")
    login_screen.geometry("400x350")
    login_screen.configure(bg="floral white")
    Label(login_screen, text="Please enter details below to login",
          bg="floral white", font=Font_tuple).pack()
    Label(login_screen, text="", bg="floral white").pack()

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()

    global username_login_entry
    global password_login_entry

    Label(login_screen, text="Username * ",
          bg="floral white", font=Font_tuple).pack()
    username_login_entry = Entry(
        login_screen, textvariable=username_verify, font=Font_tuple)
    username_login_entry.pack()
    Label(login_screen, text="", bg="floral white", font=Font_tuple).pack()
    Label(login_screen, text="Password * ",
          bg="floral white", font=Font_tuple).pack()
    password_login_entry = Entry(
        login_screen, textvariable=password_verify, show='*', font=Font_tuple)
    password_login_entry.pack()
    Label(login_screen, bg="floral white", text="", font=Font_tuple).pack()
    Button(login_screen, bg="gray17", fg="white", text="Login", width=10,
           height=1, command=login_verify, font=Font_tuple).pack()

# Implementing event on register button
def register_user():

    username_info = username.get()
    password_info = password.get()
    pin_info = pin.get()
    # Storing in database

    str = "SELECT Usernames FROM UserDetails where Usernames='%s'"
    args = (username_info,)
    cursor.execute(str % args)

    row = cursor.fetchone()

    if row is None:
        str = "insert into UserDetails(Usernames,Password,PIN) values('%s','%s','%d')"
        args = (username_info, password_info, int(pin_info))
        print(args)

        try:
            cursor.execute(str % args)
            str = 'select * from UserDetails'
            cursor.execute(str)
            myConnection.commit()

        except:
            myConnection.rollback()
            print("Error")
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        pin_entry.delete(0, END)

        Label(register_screen, bg="floral white",
            text="Registration Success", fg="green", font=Font_tuple).pack()
    else:
        Label(register_screen, bg="floral white",
            text="Username already taken!", fg="red", font=Font_tuple).pack()


# Implementing event on login button
def login_verify():
    username1 = username_verify.get()
    password1 = password_verify.get()
    username_login_entry.delete(0, END)
    password_login_entry.delete(0, END)
    # take from database here
    pin = 111111
    str = "SELECT Usernames,Password,PIN FROM UserDetails where Usernames='%s'"
    args = (username1,)
    cursor.execute(str % args)
    print("Worked")
    row = cursor.fetchone()
    print(row)
    if row is None:
        user_not_found()
    else:
        if row[1] == password1:
            loggedInUsername = username1
            login_sucess(loggedInUsername)
        else:
            password_not_recognised()

# Pop Up function for showing Login success
def login_sucess(loggedInUsername):
    global login_success_screen
    login_success_screen = Toplevel(login_screen)
    login_success_screen.title("Success")
    login_success_screen.configure(bg="floral white")
    login_success_screen.geometry("250x150")
    Label(login_success_screen, bg="floral white",
          text="Login Success", font=Font_tuple).pack()

    Button(login_success_screen, bg="gray17", fg="white", text="OK", font=("Comic Sans Ms", 10), command=lambda: [
           delete_login_success(), delete_main_screen(), create_window(loggedInUsername)]).pack()

# Designing popup for login invalid password
def password_not_recognised():
    global password_not_recog_screen
    password_not_recog_screen = Toplevel(login_screen)
    password_not_recog_screen.title("Error Invalid Password")
    password_not_recog_screen.geometry("200x100")
    password_not_recog_screen.configure(bg='floral white')
    Label(password_not_recog_screen, text="Invalid Password ",bg="floral white", font=Font_tuple).pack()
    Button(password_not_recog_screen,bg='gray17',fg='white', text="OK", font=("Comic Sans Ms", 10),
           command=delete_password_not_recognised).pack()

# Designing popup for user not found


def user_not_found():
    global user_not_found_screen
    user_not_found_screen = Toplevel(login_screen)
    user_not_found_screen.title("Error User Not Found")
    user_not_found_screen.geometry("200x100")
    user_not_found_screen.configure(bg='floral white')
    Label(user_not_found_screen, text="User Not Found",bg="floral white", font=Font_tuple).pack()
    Button(user_not_found_screen, text="OK",bg='gray17',fg='white',font=("Comic Sans Ms", 10),
           command=delete_user_not_found_screen).pack()

# Deleting popups
def delete_login_success():
    login_success_screen.destroy()


def delete_password_not_recognised():
    password_not_recog_screen.destroy()


def delete_user_not_found_screen():
    user_not_found_screen.destroy()


def delete_main_screen():
    main_screen.destroy()

# Designing Main(first) window
def main_account_screen():
    global main_screen
    main_screen = Tk()
    main_screen.geometry("500x320")
    main_screen.title("Account Login")
    main_screen.configure(bg="floral white")
    Label(text="Select Your Choice", width="300",
          bg="floral white", height="2", font=Font_tuple).pack()
    Label(text="", bg="floral white").pack()
    Button(text="Login", height="2", bg="gray17", fg="white",
           width="30", font=Font_tuple, command=login).pack()
    Label(bg="floral white", text="").pack()
    Button(text="Register", height="2", bg="gray17", fg="white",
           width="30", font=Font_tuple, command=register).pack()

    main_screen.mainloop()

main_account_screen()

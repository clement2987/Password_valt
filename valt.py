import csv
import os
import ctypes
from tkinter import *
from werkzeug.security import check_password_hash, generate_password_hash

#global veriables
PATH = "program_files/stored"
PASSWORDS = []
READ_ME = '...'
root = Tk()
root.geometry('650x450')
root.title('password Valt')

#password encryption/decryption
def hash(n):
    password =''.join(reversed(n))

    s = ''
    for letter in password:
        s += f'{ord(letter)+3:03}'

    n = int(s)

    coded = str(hex(n))
    coded = coded[2:]
    return coded


def unhash(n):
    n = '0x' + n
    hashed = int(n, 0)

    finish = ''

    while hashed > 0:
        finish += chr(hashed%1000-3)
        hashed = hashed // 1000

    return finish

#create hidden folder path to where passwords are stored
def create_prep(path):
    if not os.path.exists(path):
        os.makedirs(path)
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ret = ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)

#check if path exists, if not assume first time user
def check_path(path):
    if not os.path.exists(path):
        return False
    else:
        return True
    
#save master password hash
def save_master(password):
    master_hash = generate_password_hash(password)
    global PATH
    filepath = PATH + '/master.txt'
    with open(filepath, 'w') as file:
        file.write(master_hash)

#check master password hash
def check_master(password):
    global PATH
    with open(PATH + '/master.txt', 'r') as file:
        master_hash = file.read()
    return check_password_hash(master_hash, password)

#save and retrive passwords from disk
def save_list():
    global PATH, PASSWORDS
    file_path = PATH + '/data.csv'
    with open(file_path, 'w') as f:
        writer = csv.DictWriter(f, fieldnames=["service", "username", "password"])
        writer.writeheader()
        for row in PASSWORDS:
            writer.writerow(row)

def load_list():
    global PATH, PASSWORDS
    file_path = PATH + '/data.csv'
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                PASSWORDS.append({"service": row['service'], "username": row['username'], "password": row['password']})
    except FileNotFoundError:
        pass

#gui sign un/up specific functions
def quit():
    global root
    root.destroy()

def change_frames():
    retrive.pack()

def sign_in(password):
    if check_master(password) == True:
        returning_user.pack_forget()
        change_frames()
    else:
        Label(returning_user, text='Incorrect Password').pack()


def sign_up(password, password2):
    global PATH
    if len(password) < 4:
        Label(new_user, text="Try making a password that is at least 4 characters long\nwe are not that big on security\n but lets at least try to make it hard for the badgyuy").pack()
    
    elif password == password2:
        create_prep(PATH)
        save_master(password)
        new_user.pack_forget()
        change_frames()
    else:
        Label(new_user, text="Passwords have to match\nelse how do i know you will remember it if you\nremember it after this short amount of time?").pack()



#create lable frames
new_user = LabelFrame(root, text='Choose Master Password')
Label(new_user, text='Password').pack()
password1 = Entry(new_user, show='*')
password1.pack()
Label(new_user, text='Enter password again').pack()
password2 = Entry(new_user, show='*')
password2.pack()
Button(new_user, text='Create', command=lambda: sign_up(password1.get(), password2.get())).pack()
Button(new_user, text='Quit', command=quit).pack()

returning_user = LabelFrame(root, text='Sign In')
pas = Label(returning_user, text='Password').pack()
password = Entry(returning_user, show='*')
password.pack()
Button(returning_user, text='Submit', command=lambda: sign_in(password.get())).pack()
Button(returning_user, text='Quit', command=quit).pack()

#choose which frame to start with depending on if there is alreade a file here
if check_path(PATH) == False:
    new_user.pack()
else:
    load_list()
    returning_user.pack()

#make the main frame
retrive = LabelFrame(root, text='Show Password')

#functions needed to drive the main frame before packing it
# Function for checking the
# key pressed and updating
# the listbox
def checkkey(event):
       
    value = event.widget.get()
    #print(value)
      
    # get data from l
    if value == '':
        data = l
    else:
        data = []
        for item in l:
            if value.lower() in item.lower():
                data.append(item)                
   
    # update data in listbox
    update(data)
   
   
def update(data):
      
    # clear previous data
    lb.delete(0, 'end')
   
    # put new data
    for item in data:
        lb.insert('end', item)


#when an item in the list is clicked fill the entry with selection
def fill_entry(event):
    subject = lb.curselection()
    if not subject:
        return
    e.delete(0, END)
    e.insert(0, lb.get(subject))
  
  
# Driver code
l = []

def pop_list():
    l.clear()
    for d in PASSWORDS:
        l.append(d['service'])

pop_list()

def show_password():
    message_window = Toplevel()
    message_window.geometry('350x150')
    message_window.title(f"{e.get()}")

    if e.get().title() in l:
        for i in PASSWORDS:
            if i['service'] == e.get().title():
                Label(message_window, text=f"Username: ").grid(row=0, column=0)
                u = Entry(message_window)
                u.grid(row=0, column=1)
                u.insert(0, f"{i['username']}")
                Label(message_window, text=f"Password: ").grid(row=0, column=2)
                p = Entry(message_window)
                p.grid(row=0, column=3)
                p.insert(0, f"{unhash(i['password'])}")
                Button(message_window, text='Done', command=message_window.destroy).grid(row=1, column=2)
    else:
        Label(message_window, text='No match in saved passwords').pack()
        Button(message_window, text='Done', command=message_window.destroy).pack()


def edit_password_dict(u, p, window):

    for i in PASSWORDS:
        if i['service'] == e.get().title().strip():
            i['username'] = u.title().strip()
            i['password'] = hash(p.strip())
            window.configure(bg='green')
            window.after(1000, lambda: window.configure(bg='light grey'))
            save_list()       
            return


def edit_password():
    message_window = Toplevel()
    message_window.geometry('350x150')
    message_window.title(f"{e.get()}")

    if e.get().title() in l:
        for i in PASSWORDS:
            if i['service'] == e.get().title():
                Label(message_window, text=f"Username: ").grid(row=0, column=0)
                u = Entry(message_window)
                u.grid(row=0, column=1)
                u.insert(0, f"{i['username']}")
                Label(message_window, text=f"Password: ").grid(row=0, column=2)
                p = Entry(message_window)
                p.grid(row=0, column=3)
                p.insert(0, f"{unhash(i['password'])}")

                Button(message_window, text='Save', command=lambda: edit_password_dict(u.get(), p.get(), message_window)).grid(row=1, column=1)
                Button(message_window, text='Back', command=message_window.destroy).grid(row=1, column=2)
    else:
        Label(message_window, text='No match in saved passwords').pack()
        Button(message_window, text='Done', command=message_window.destroy).pack()


def save_password_dict(service, username, password, window):

    if service.get == '' or password.get() == '' or username.get() == '':
        window.configure(bg='red')
        alert = Label(window, text='Missing Username, Service or Password')
        alert.grid(row=4, column=0)
        window.after(1000, lambda: [window.configure(bg='light grey'), alert.destroy()]) 
        
        return
    

    for i in PASSWORDS:
        if i['service'] == service.get().title().strip():
            window.configure(bg='red')
            alert = Label(window, text='This service already exists')
            alert.grid(row=4, column=0)
            window.after(1000, lambda: [window.configure(bg='light grey'), alert.destroy()]) 
            
            return

    new = {
        'service': service.get().title().strip(),
        'username': username.get().strip(),
        'password': hash(password.get().strip())
    }

    password.delete(0, END)
    service.delete(0, END)
    username.delete(0, END)

    PASSWORDS.append(new)
    pop_list()
    update(l)
    save_list()
    window.configure(bg='green')
    alert = Label(window, text='Saved Successfully')
    alert.grid(row=4, column=0)
    window.after(1000, lambda: [window.configure(bg='light grey'), alert.destroy()]) 
    service.delete(0, END)

def save_password():
    message_window = Toplevel()
    message_window.geometry('350x150')
    message_window.title(f"{'New Password'}")
    Label(message_window, text='Service').grid(row=0, column=0)
    Label(message_window, text='Username').grid(row=1, column=0)
    Label(message_window, text='Password').grid(row=2, column=0)
    service = Entry(message_window)
    service.grid(row=0, column=1)
    username = Entry(message_window)
    username.grid(row=1, column=1)
    password = Entry(message_window)
    password.grid(row=2, column=1)
    Button(message_window, text='Save', command=lambda: save_password_dict(service, username, password, message_window)).grid(row=3, column=0)
    Button(message_window, text='Back', command=message_window.destroy).grid(row=3, column=1)

def delete_password_dict(service, message, b1, b2):
    PASSWORDS.remove(service)
    message.config(text='Password Deleted')
    b2.config(text='Done')
    b1.destroy()
    pop_list()
    update(l)
    save_list()


def delete_password():
    message_window = Toplevel()
    message_window.geometry('350x150')
    message_window.title(f"{e.get()}")

    if e.get().title() in l:
        for i in PASSWORDS:
            if i['service'] == e.get().title():
                dict_item = i
                li = Label(message_window, text='Delete Permanently?')
                li.grid(row=0, column=1)
                b1 = Button(message_window, text='YES', command=lambda: delete_password_dict(dict_item, li, b1, b2))
                b1.grid(row=1, column=1)
                b2 = Button(message_window, text='NO', command=message_window.destroy)
                b2.grid(row=1, column=2)
    else:
        Label(message_window, text='No match in saved passwords').pack()
        Button(message_window, text='Done', command=message_window.destroy).pack()


def change_master_file(password, new_password1, new_password2, window):
    if new_password1 == new_password2 and check_master(password) == True:
        save_master(new_password1)
        window.configure(bg='green')

def change_master():
    message_window = Toplevel()
    message_window.geometry('350x150')

    Label(message_window, text='Old Password').grid(row=0, column=0)
    Label(message_window, text='New Password').grid(row=1, column=0)
    Label(message_window, text='Retype New Password').grid(row=2, column=0)
    old = Entry(message_window)
    new1 = Entry(message_window)
    new2= Entry(message_window)
    old.grid(row=0, column=1)
    new1.grid(row=1, column=1)
    new2.grid(row=2, column=1)
    Button(message_window, text='Change Password', command=lambda: change_master_file(old.get(), new1.get(), new2.get(), message_window)).grid(row=3, column=0)
    Button(message_window, text='Back', command=message_window.destroy).grid(row=3, column=1)

        

  
#creating text box 
e = Entry(retrive)
e.grid(row=0, column=0)
e.bind('<KeyRelease>', checkkey)
  
#creating list box
lb = Listbox(retrive)
lb.grid(rowspan=5, row=1, column=0)
update(l)
lb.bind('<ButtonRelease>', fill_entry)

Button( retrive, text='show password', command=show_password).grid(row=1, column=1)
Button( retrive, text='edit password', command=edit_password).grid(row=2, column=1)
Button( retrive, text='new password', command=save_password).grid(row=3, column=1)
Button(retrive, text='delete password', command=delete_password).grid(row=4, column=1)
Button(retrive, text='Change Master', command=change_master).grid(row=5, column=1)
Button(retrive, text='Quit', command=retrive.quit).grid(row=6, column=1)

root.mainloop()
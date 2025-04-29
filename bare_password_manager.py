import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import sqlite3

# AES Encryption and Decryption Utilities
def generate_key(master_password):
    # Generate a salt (random value)
    salt = os.urandom(16)
    # Use PBKDF2 to derive a key from the master password
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(master_password.encode())
    return key, salt

def encrypt_password(password, key, salt):
    # Encrypt the password with AES
    cipher = Cipher(algorithms.AES(key), modes.GCM(salt))
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted_password).decode()

def decrypt_password(encrypted_password, key, salt):
    # Decrypt the password using AES
    cipher = Cipher(algorithms.AES(key), modes.GCM(salt))
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()
    return decrypted_password.decode()

# Database handling
def init_db():
    # SQLite DB setup
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords 
                      (website TEXT, username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

def save_password(website, username, password):
    # Save encrypted password to SQLite DB
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)', 
                   (website, username, password))
    conn.commit()
    conn.close()

def fetch_password(website):
    # Fetch encrypted password for the given website
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, password FROM passwords WHERE website = ?', (website,))
    result = cursor.fetchone()
    conn.close()
    return result

# Tkinter Interface
class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title('Password Manager')
        
        self.master_password = None
        self.key = None
        
        self.init_ui()

    def init_ui(self):
        self.master_label = tk.Label(self.master, text="Master Password")
        self.master_label.grid(row=0, column=0)
        
        self.master_password_entry = tk.Entry(self.master, show="*")
        self.master_password_entry.grid(row=0, column=1)
        
        self.login_button = tk.Button(self.master, text="Login", command=self.login)
        self.login_button.grid(row=0, column=2)
        
        self.website_label = tk.Label(self.master, text="Website")
        self.website_label.grid(row=1, column=0)
        
        self.website_entry = tk.Entry(self.master)
        self.website_entry.grid(row=1, column=1)
        
        self.username_label = tk.Label(self.master, text="Username")
        self.username_label.grid(row=2, column=0)
        
        self.username_entry = tk.Entry(self.master)
        self.username_entry.grid(row=2, column=1)
        
        self.password_label = tk.Label(self.master, text="Password")
        self.password_label.grid(row=3, column=0)
        
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.grid(row=3, column=1)
        
        self.save_button = tk.Button(self.master, text="Save", command=self.save_password)
        self.save_button.grid(row=4, column=1)
        
        self.fetch_button = tk.Button(self.master, text="Fetch", command=self.fetch_password)
        self.fetch_button.grid(row=5, column=1)

    def login(self):
        master_password = self.master_password_entry.get()
        if master_password:
            self.master_password = master_password
            self.key, salt = generate_key(self.master_password)
            init_db()
            messagebox.showinfo("Login", "Logged in successfully!")

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        encrypted_password = encrypt_password(password, self.key, os.urandom(16))
        save_password(website, username, encrypted_password)

    def fetch_password(self):
        website = self.website_entry.get()
        result = fetch_password(website)
        if result:
            username, encrypted_password = result
            decrypted_password = decrypt_password(encrypted_password, self.key, os.urandom(16))
            messagebox.showinfo("Password", f"Username: {username}\nPassword: {decrypted_password}")
        else:
            messagebox.showwarning("Fetch Error", "Website not found!")

if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

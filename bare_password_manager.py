import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import hashlib
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import json
import re

class BarePasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title('Bare Password Manager')
        self.master.geometry('800x800')

        self.master_password = None
        self.key = None
        self.salt = None
        self.passwords_db = []  # List of dicts with Website, Username, Password, Timestamp

        self.init_ui()

    def init_ui(self):
        if not self.check_master_password():
            self.prompt_for_master_password()
        else:
            self.prompt_for_login()

    def check_master_password(self):
        try:
            with open("master_password.enc", "rb") as f:
                return True
        except FileNotFoundError:
            return False

    def prompt_for_master_password(self):
        self.clear_widgets()

        self.form_frame = tk.Frame(self.master)
        self.form_frame.place(relx=0.5, rely=0.5, anchor='center')

        self.title_label = tk.Label(self.form_frame, text="Create Your Master Password", font=('Arial', 16))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=10)

        logo = Image.open("logo.png").resize((200, 200))
        logo_img = ImageTk.PhotoImage(logo)
        self.logo_label = tk.Label(self.form_frame, image=logo_img)
        self.logo_label.image = logo_img
        self.logo_label.grid(row=1, column=0, columnspan=2, pady=10)

        self.master_password_label = tk.Label(self.form_frame, text="Master Password")
        self.master_password_label.grid(row=2, column=0, sticky='e')
        self.master_password_entry = tk.Entry(self.form_frame, show="*")
        self.master_password_entry.grid(row=2, column=1, pady=5)

        self.confirm_password_label = tk.Label(self.form_frame, text="Confirm Password")
        self.confirm_password_label.grid(row=3, column=0, sticky='e')
        self.confirm_password_entry = tk.Entry(self.form_frame, show="*")
        self.confirm_password_entry.grid(row=3, column=1, pady=5)

        self.save_button = tk.Button(self.form_frame, text="Save Master Password", command=self.save_master_password)
        self.save_button.grid(row=4, column=0, columnspan=2, pady=10)

    # Master password validations
    def is_strong_password(self, password):
        """Validates password strength: 12+ chars, upper, lower, number, special."""
        if len(password) < 12:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

    def save_master_password(self):
        master_password = self.master_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if master_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        if not self.is_strong_password(master_password):
            messagebox.showerror(
                "Weak Password",
                "Password must be at least 12 characters long and include:\n"
                "- An uppercase letter\n"
                "- A lowercase letter\n"
                "- A number\n"
                "- A special character"
            )
            return

        self.salt = os.urandom(16)
        self.key = self.derive_key(master_password)
        encrypted_password = self.encrypt_password(master_password.encode('utf-8'))

        with open("master_password.enc", "wb") as f:
            f.write(self.salt)
            f.write(encrypted_password)

        messagebox.showinfo("Success", "Master password created successfully!")
        self.prompt_for_login()

    def derive_key(self, master_password):
        return hashlib.pbkdf2_hmac('sha256', master_password.encode(), self.salt, 100000)

    def encrypt_password(self, password_bytes):
        padder = padding.PKCS7(128).padder()
        padded_password = padder.update(password_bytes) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
        return iv + encrypted_password

    def prompt_for_login(self):
        self.clear_widgets()

        self.form_frame = tk.Frame(self.master)
        self.form_frame.place(relx=0.5, rely=0.5, anchor='center')

        self.title_label = tk.Label(self.form_frame, text="Enter Master Password", font=('Arial', 16))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=10)

        logo = Image.open("logo.png").resize((650, 650))
        logo_img = ImageTk.PhotoImage(logo)
        self.logo_label = tk.Label(self.form_frame, image=logo_img)
        self.logo_label.image = logo_img
        self.logo_label.grid(row=1, column=0, columnspan=2, pady=10)

        self.master_password_label = tk.Label(self.form_frame, text="Master Password")
        self.master_password_label.grid(row=2, column=0, sticky='e')
        self.master_password_entry = tk.Entry(self.form_frame, show="*")
        self.master_password_entry.grid(row=2, column=1, pady=5)

        self.login_button = tk.Button(self.form_frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=10)

    def login(self):
        master_password = self.master_password_entry.get()

        with open("master_password.enc", "rb") as f:
            self.salt = f.read(16)
            encrypted_password = f.read()

        self.key = self.derive_key(master_password)
        decrypted_password = self.decrypt_password(encrypted_password)

        if master_password == decrypted_password:
            messagebox.showinfo("Login", "Logged in successfully!")
            self.show_main_gui()
        else:
            messagebox.showerror("Error", "Incorrect master password!")

    def decrypt_password(self, encrypted_password):
        iv = encrypted_password[:16]
        cipher_text = encrypted_password[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_password = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        password = unpadder.update(padded_password) + unpadder.finalize()

        return password.decode('utf-8')

    def show_main_gui(self):
        self.clear_widgets()
        self.load_db()

        # How to use the app
        self.explanation_label = tk.Label(self.master, 
            text="Welcome to Bare Password Manager! \n\n" 
                "This application helps you securely manage your passwords.\n" 
                "Use the toolbar at the top to access the following features:\n\n"
                "\u2022 Add Entry: Add new passwords for your accounts and websites.\n"
                "\u2022 Edit Entry: Modify or update the details of your stored passwords.\n"
                "\u2022 Change Master Password: Update your master password for added security.\n\n"
                "Make sure to choose strong passwords and keep them safe.\n", 
            font=('Montserrat', 0), anchor='w', justify='left')
        self.explanation_label.pack(side=tk.TOP, padx=2, pady=10)

        toolbar = tk.Frame(self.master)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        def create_icon_button(parent, color, text, command):
            frame = tk.Frame(parent)
            frame.pack(side=tk.LEFT, padx=5, pady=5)

            canvas = tk.Canvas(frame, width=12, height=12, highlightthickness=0, bg=parent["bg"])
            canvas.create_rectangle(2, 2, 12, 12, fill=color, outline=color)
            canvas.pack(side=tk.LEFT)

            button = tk.Button(frame, text=text, command=command)
            button.pack(side=tk.LEFT)

        create_icon_button(toolbar, 'green', "Add Entry", self.add_entry_popup)
        create_icon_button(toolbar, 'orange', "Edit Entry", self.edit_selected_entry)
        create_icon_button(toolbar, 'blue', "Import DB", self.import_db)
        create_icon_button(toolbar, 'purple', "Export DB", self.export_db)
        create_icon_button(toolbar, 'red', "Change Master Password", self.change_master_password_popup)

        columns = ('Website/App', 'Username', 'Password', 'Last Updated', 'Show')
        self.tree = ttk.Treeview(self.master, columns=columns, show='headings', selectmode='browse')

        for col in columns:
            self.tree.heading(col, text=col)
            anchor = 'center' if col != 'Show' else 'center'
            width = 50 if col == 'Show' else 150
            self.tree.column(col, width=width, anchor=anchor)

        self.tree.pack(fill='both', expand=True)
        self.tree.bind("<Button-1>", self.reveal_password)

        for entry in self.passwords_db:
            self.tree.insert('', 'end', values=(
                entry['website'],
                entry['username'],
                '*' * len(entry['password']),
                entry['timestamp'],
                '👁️'
            ))
    
    def change_master_password_popup(self):
        popup = tk.Toplevel(self.master)
        popup.title("Change Master Password")
        popup.geometry("400x350")

        tk.Label(popup, text="Old Master Password").grid(row=0, column=0)
        old_password_entry = tk.Entry(popup, show="*")
        old_password_entry.grid(row=0, column=1)

        tk.Label(popup, text="New Master Password").grid(row=1, column=0)
        new_password_entry = tk.Entry(popup, show="*")
        new_password_entry.grid(row=1, column=1)

        tk.Label(popup, text="Confirm New Password").grid(row=2, column=0)
        confirm_new_password_entry = tk.Entry(popup, show="*")
        confirm_new_password_entry.grid(row=2, column=1)

        def save_new_master_password():
            old_master_password = old_password_entry.get()
            new_master_password = new_password_entry.get()
            confirm_new_password = confirm_new_password_entry.get()

            # Verify old master password
            with open("master_password.enc", "rb") as f:
                self.salt = f.read(16)
                encrypted_password = f.read()

            self.key = self.derive_key(old_master_password)
            decrypted_password = self.decrypt_password(encrypted_password)

            if old_master_password != decrypted_password:
                messagebox.showerror("Error", "Old master password is incorrect!")
                return

            # Check if the new passwords match
            if new_master_password != confirm_new_password:
                messagebox.showerror("Error", "New passwords do not match!")
                return

            # Validate new password strength using the existing method
            if not self.is_strong_password(new_master_password):
                messagebox.showerror(
                    "Weak Password",
                    "New password must be at least 12 characters long and include:\n"
                    "- An uppercase letter\n"
                    "- A lowercase letter\n"
                    "- A number\n"
                    "- A special character"
                )
                return

            # Derive the new key and encrypt the new master password
            self.salt = os.urandom(16)  # Generate a new salt
            self.key = self.derive_key(new_master_password)
            encrypted_new_password = self.encrypt_password(new_master_password.encode('utf-8'))

            # Save the new master password to the file
            with open("master_password.enc", "wb") as f:
                f.write(self.salt)
                f.write(encrypted_new_password)

            messagebox.showinfo("Success", "Master password changed successfully!")
            popup.destroy()
            self.prompt_for_login()  # Prompt to log in with the new password

        save_button = tk.Button(popup, text="Save New Master Password", command=save_new_master_password)
        save_button.grid(row=3, column=1, pady=10)

    def add_entry_popup(self):
        popup = tk.Toplevel(self.master)
        popup.title("Add Entry")
        popup.geometry("400x350")

        tk.Label(popup, text="Website/App").grid(row=0, column=0)
        website_entry = tk.Entry(popup)
        website_entry.grid(row=0, column=1)

        tk.Label(popup, text="Username").grid(row=1, column=0)
        username_entry = tk.Entry(popup)
        username_entry.grid(row=1, column=1)

        tk.Label(popup, text="Password").grid(row=2, column=0)
        password_entry = tk.Entry(popup, show="*")
        password_entry.grid(row=2, column=1)

        def toggle_password():
            if password_entry.cget('show') == '*':
                password_entry.config(show='')
            else:
                password_entry.config(show='*')

        eye_button = tk.Button(popup, text="👁️", command=toggle_password)
        eye_button.grid(row=2, column=2)

        def save():
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            entry = {
                'website': website,
                'username': username,
                'password': password,
                'timestamp': timestamp
            }

            self.passwords_db.append(entry)
            self.tree.insert('', 'end', values=(website, username, '*' * len(password), timestamp, '👁️'))
            self.save_db()
            popup.destroy()

        save_button = tk.Button(popup, text="Save", command=save)
        save_button.grid(row=3, column=1, pady=10)

    def reveal_password(self, event):
        item_id = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)

        if not item_id:
            return

        values = list(self.tree.item(item_id, 'values'))

        # Column #5 = Show/Hide
        if column == '#5':
            for entry in self.passwords_db:
                if entry['website'] == values[0] and entry['username'] == values[1]:
                    if values[4] in ['Show', '👁️']:
                        values[2] = entry['password']
                        values[4] = '🙈'
                    else:
                        values[2] = '*' * len(entry['password'])
                        values[4] = '👁️'
                    self.tree.item(item_id, values=values)
                    break

        # Column #3 = Password (click to copy to clipboard)
        elif column == '#3':
            for entry in self.passwords_db:
                if entry['website'] == values[0] and entry['username'] == values[1]:
                    self.master.clipboard_clear()
                    self.master.clipboard_append(entry['password'])
                    self.master.update()  # Keeps clipboard after app closes
                    messagebox.showinfo("Copied", "Password copied to clipboard.")
                    break
    
    def edit_selected_entry(self):
        messagebox.showinfo("Edit", "Edit feature not yet implemented.")

    def import_db(self):
        messagebox.showinfo("Import", "Import feature not yet implemented.")

    def export_db(self):
        messagebox.showinfo("Export", "Export feature not yet implemented.")

    # DB handling functions

    def save_db(self):
        # Encrypt the passwords_db and save it to a file
        encrypted_data = self.encrypt_data(self.passwords_db)
        with open("passwords_db.enc", "wb") as f:  # Save as .enc to indicate encrypted data
            f.write(encrypted_data)

    def load_db(self):
        # Decrypt the data before loading it into passwords_db
        try:
            with open("passwords_db.enc", "rb") as f:
                encrypted_data = f.read()
            self.passwords_db = self.decrypt_data(encrypted_data)  # Decrypt the data
        except FileNotFoundError:
            self.passwords_db = []

    def clear_widgets(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    # Encrypt and Decrypt functions for the database

    def encrypt_data(self, data):
        json_data = json.dumps(data).encode('utf-8')  # Convert data to JSON string and encode to bytes
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(json_data) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return iv + encrypted_data  # Prefix the iv to the encrypted data for decryption later

    def decrypt_data(self, encrypted_data):
        iv = encrypted_data[:16]
        cipher_text = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return json.loads(decrypted_data.decode('utf-8'))  # Convert decrypted bytes back to JSON

root = tk.Tk()
app = BarePasswordManager(root)
root.mainloop()
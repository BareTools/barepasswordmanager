import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import hashlib
import os
import sys
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import json
import re
import time

class BarePasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title('Bare Password Manager')
        self.master.geometry('1200x800')

        self.master_password = None
        self.key = None
        self.salt = None
        self.passwords_db = []  # List of dicts with Website, Username, Password, Timestamp

         # Initialize AppData directory
        self.app_data_dir = self.get_app_data_directory()
        os.makedirs(self.app_data_dir, exist_ok=True)

        self.last_activity_time = time.time()  # Initialize last activity time
        self.timeout_seconds = 5 * 60  # 5 minutes timeout (customize as needed)

        self.master.bind_all("<Any-KeyPress>", self.reset_activity_timer)
        self.master.bind_all("<Any-Button>", self.reset_activity_timer)

        self.init_ui()

        self.update_title()  # Call to update the title with remaining time
        self.check_inactivity()  # Start checking for inactivity

    def init_ui(self):
        if not self.check_master_password():
            self.prompt_for_master_password()
        else:
            self.prompt_for_login()

    # Check if master password and password database exist
    def get_app_data_directory(self):
        """Get the AppData directory path for the current platform"""
        if sys.platform == 'win32':
            app_data = os.getenv('APPDATA')
            return os.path.join(app_data, 'BarePasswordManager')
        elif sys.platform == 'darwin':  # macOS
            home = os.path.expanduser('~')
            return os.path.join(home, 'Library', 'Application Support', 'BarePasswordManager')
        else:  # Linux/Unix
            home = os.path.expanduser('~')
            return os.path.join(home, '.barepasswordmanager')

    def get_master_password_path(self):
        """Get full path to master password file"""
        return os.path.join(self.app_data_dir, 'master_password.enc')

    def get_db_path(self):
        """Get full path to password database file"""
        return os.path.join(self.app_data_dir, 'passwords_db.enc')

    def check_master_password(self):
        try:
            with open(self.get_master_password_path(), "rb") as f:
                return True
        except FileNotFoundError:
            return False

    def prompt_for_master_password(self):
        self.clear_widgets()

        self.form_frame = tk.Frame(self.master)
        self.form_frame.place(relx=0.5, rely=0.5, anchor='center')

        self.title_label = tk.Label(self.form_frame, text="Create Your Master Password", font=('Arial', 16))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=10)

        logo = Image.open("logo.png").resize((500, 500))
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

        with open(self.get_master_password_path(), "wb") as f:
            f.write(self.salt)
            f.write(encrypted_password)

        messagebox.showinfo("Success", "Master password created successfully!")
        self.prompt_for_login()

    def derive_key(self, master_password):
        return hashlib.pbkdf2_hmac('sha256', master_password.encode(), self.salt, 100000)

    def encrypt_password(self, password_bytes):
        # Pad the password before encryption
        padder = padding.PKCS7(128).padder()  # 128-bit block size for AES
        padded_password = padder.update(password_bytes) + padder.finalize()

        iv = os.urandom(16)  # Generate a random IV for each encryption
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

        # Return IV + encrypted password as one concatenated string
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

        # Read the salt and encrypted password from the file
        with open(self.get_master_password_path(), "rb") as f:
            self.salt = f.read(16)  # Read the salt (first 16 bytes)
            encrypted_password = f.read()  # Read the encrypted password data

        # Derive the key using the entered master password and the stored salt
        self.key = self.derive_key(master_password)

        # Decrypt the stored password using the derived key
        decrypted_password = self.decrypt_password(encrypted_password, master_password)

        if master_password == decrypted_password:
            messagebox.showinfo("Login", "Logged in successfully!")
            self.show_main_gui()
        else:
            messagebox.showerror("Error", "Incorrect master password!")

    def decrypt_password(self, encrypted_password, master_password):
        iv = encrypted_password[:16]
        cipher_text = encrypted_password[16:]

        # Derive the key using the provided master password and the salt
        key = self.derive_key(master_password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        padded_data = decryptor.update(cipher_text) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return decrypted_data.decode('utf-8')

    def show_main_gui(self):
        self.clear_widgets()
        self.load_db()
        self.update_title()

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

        # Create main toolbar frame
        toolbar = tk.Frame(self.master)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        # Left side toolbar for action buttons
        left_toolbar = tk.Frame(toolbar)
        left_toolbar.pack(side=tk.LEFT)

        def create_icon_button(parent, color, text, command):
            frame = tk.Frame(parent)
            frame.pack(side=tk.LEFT, padx=5, pady=5)

            canvas = tk.Canvas(frame, width=13, height=13, highlightthickness=0, bg=parent["bg"])
            canvas.create_rectangle(2, 2, 13, 13, fill=color, outline=color)
            canvas.pack(side=tk.LEFT)

            button = tk.Button(frame, text=text, command=command)
            button.pack(side=tk.LEFT)

        # Action buttons
        create_icon_button(left_toolbar, 'green', "Add Entry", self.add_entry_popup)
        create_icon_button(left_toolbar, 'red', "Delete Entry", self.delete_selected_entry)
        create_icon_button(left_toolbar, 'orange', "Edit Entry", self.edit_selected_entry)
        create_icon_button(left_toolbar, 'blue', "Import DB", self.import_db)
        create_icon_button(left_toolbar, 'purple', "Export DB", self.export_db)
        create_icon_button(left_toolbar, 'black', "Change Master Password", self.change_master_password_popup)

        # Right side toolbar for search
        right_toolbar = tk.Frame(toolbar)
        right_toolbar.pack(side=tk.RIGHT)

        # Search components
        search_frame = tk.Frame(right_toolbar)
        search_frame.pack(side=tk.RIGHT, padx=5)

        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = tk.Entry(search_frame, width=25)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind("<KeyRelease>", self.filter_treeview)

        # Clear search button with better styling
        clear_search_btn = tk.Button(
            search_frame, 
            text="×", 
            command=self.clear_search,
            font=('Arial', 10, 'bold'),
            fg='red',
            relief=tk.FLAT,
            bd=0
        )
        clear_search_btn.pack(side=tk.LEFT)

        # Create the treeview with scrollbars
        tree_frame = tk.Frame(self.master)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Vertical scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Horizontal scrollbar
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        columns = ('Website/App', 'Username', 'Password', 'Last Updated', 'Show', 'Strength')
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show='headings',
            selectmode='browse',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )

        # Configure scrollbars
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Style for the headers
        style = ttk.Style()
        style.configure("Treeview.Heading", font=('Helvetica', 11, 'bold'), background="#d9d9d9", foreground="black")

        # Configure columns
        for col in columns:
            self.tree.heading(col, text=col)
            anchor = 'center' if col != 'Show' else 'center'
            width = 60 if col == 'Show' else 150
            self.tree.column(col, width=width, anchor=anchor)

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Button-1>", self.reveal_password)

        # Populate the treeview with all entries initially
        self.filter_treeview()

    def change_master_password_popup(self):
        popup = tk.Toplevel(self.master)
        popup.title("Change Master Password")

        # Create a frame for better organization
        frame = tk.Frame(popup, padx=10, pady=10)
        frame.pack()

        # Old password
        tk.Label(frame, text="Old Master Password").grid(row=0, column=0, sticky='e')
        old_password_entry = tk.Entry(frame, show="*")
        old_password_entry.grid(row=0, column=1, pady=5)

        # New password
        tk.Label(frame, text="New Master Password").grid(row=1, column=0, sticky='e')
        new_password_entry = tk.Entry(frame, show="*")
        new_password_entry.grid(row=1, column=1, pady=5)

        # Confirm new password
        tk.Label(frame, text="Confirm New Password").grid(row=2, column=0, sticky='e')
        confirm_new_password_entry = tk.Entry(frame, show="*")
        confirm_new_password_entry.grid(row=2, column=1, pady=5)

        # Button frame
        button_frame = tk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        def save_new_master_password():
            old_master_password = old_password_entry.get()
            new_master_password = new_password_entry.get()
            confirm_new_password = confirm_new_password_entry.get()

            # Verify old master password
            with open("master_password.enc", "rb") as f:
                old_salt = f.read(16)  # Read the salt
                encrypted_password = f.read()  # Read the encrypted password data

            # Derive the old key
            old_key = hashlib.pbkdf2_hmac('sha256', old_master_password.encode(), old_salt, 100000)

            try:
                # Decrypt with old key
                cipher = Cipher(algorithms.AES(old_key), modes.CBC(encrypted_password[:16]), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(encrypted_password[16:]) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                decrypted_password = unpadder.update(padded_data) + unpadder.finalize()
                decrypted_password = decrypted_password.decode('utf-8')
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
                return

            if old_master_password != decrypted_password:
                messagebox.showerror("Error", "Old master password is incorrect!")
                return

            if new_master_password != confirm_new_password:
                messagebox.showerror("Error", "New passwords do not match!")
                return

            if not self.is_strong_password(new_master_password):
                messagebox.showerror(
                    "Weak Password",
                    "Password must be at least 12 characters long and include:\n"
                    "- An uppercase letter\n- A lowercase letter\n"
                    "- A number\n- A special character"
                )
                return

            # Generate new salt and key
            new_salt = os.urandom(16)
            new_key = hashlib.pbkdf2_hmac('sha256', new_master_password.encode(), new_salt, 100000)

            # Re-encrypt the database with the new key
            try:
                # Load with old key
                self.key = old_key
                self.load_db()
                
                # Save with new key
                self.salt = new_salt
                self.key = new_key
                self.save_db()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to re-encrypt database: {e}")
                return

            # Encrypt and save new master password
            encrypted_new_password = self.encrypt_password(new_master_password.encode('utf-8'))
            with open("master_password.enc", "wb") as f:
                f.write(new_salt)
                f.write(encrypted_new_password)

            messagebox.showinfo("Success", "Master password changed successfully!")
            popup.destroy()
            self.prompt_for_login()

        # Save button
        tk.Button(button_frame, text="Save", command=save_new_master_password).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=popup.destroy).pack(side=tk.LEFT, padx=5)

    def add_entry_popup(self):
        popup = tk.Toplevel(self.master)
        popup.title("Add Entry")
        popup.geometry("400x350")
        popup.resizable(False, False)  # Prevent resizing of the popup

        # Create a frame to contain the grid layout
        frame = tk.Frame(popup)
        frame.grid(row=0, column=0, padx=10, pady=10)

        # Create labels with larger font size and align them to the left (sticky='w')
        tk.Label(frame, text="Website/App", font=('Arial', 12), anchor='w').grid(row=0, column=0, pady=10, sticky='w')
        website_entry = tk.Entry(frame, font=('Arial', 12), width=30)
        website_entry.grid(row=0, column=1, pady=10)

        tk.Label(frame, text="Username", font=('Arial', 12), anchor='w').grid(row=1, column=0, pady=10, sticky='w')
        username_entry = tk.Entry(frame, font=('Arial', 12), width=30)
        username_entry.grid(row=1, column=1, pady=10)

        tk.Label(frame, text="Password", font=('Arial', 12), anchor='w').grid(row=2, column=0, pady=10, sticky='w')
        password_entry = tk.Entry(frame, font=('Arial', 12), width=30, show="*")
        password_entry.grid(row=2, column=1, pady=10)

        # Toggle password visibility function
        def toggle_password():
            if password_entry.cget('show') == '*':
                password_entry.config(show='')
            else:
                password_entry.config(show='*')

        # Eye button to toggle password visibility
        eye_button = tk.Button(frame, text="👁️", font=('Arial', 12), command=toggle_password)
        eye_button.grid(row=2, column=2, padx=10, pady=10)

        # Add save button
        save_button = tk.Button(frame, text="Save", font=('Arial', 12), width=20, command=lambda: save())
        save_button.grid(row=3, columnspan=3, pady=20)

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

    def delete_selected_entry(self):
        """Delete the currently selected entry from the database"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No entry selected!")
            return
        
        # Get the values from the selected row
        values = self.tree.item(selected_item, 'values')
        website = values[0]
        username = values[1]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", 
                                f"Delete entry for:\nWebsite: {website}\nUsername: {username}?"):
            return
        
        # Find and remove the entry from passwords_db
        for i, entry in enumerate(self.passwords_db):
            if entry['website'] == website and entry['username'] == username:
                del self.passwords_db[i]
                break
        
        # Remove from treeview and save database
        self.tree.delete(selected_item)
        self.save_db()
        messagebox.showinfo("Success", "Entry deleted successfully")

    # DB handling functions

    def save_db(self):
        # Encrypt the passwords_db and save it to a file
        encrypted_data = self.encrypt_data(self.passwords_db)
        with open(self.get_db_path(), "wb") as f:  # Save as .enc to indicate encrypted data
            f.write(encrypted_data)

    def load_db(self):
        # Decrypt the data before loading it into passwords_db
        try:
            with open(self.get_db_path(), "rb") as f:
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

        return iv + encrypted_data  # Return IV + encrypted data

    def decrypt_data(self, encrypted_data):
        iv = encrypted_data[:16]
        cipher_text = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return json.loads(decrypted_data.decode('utf-8'))  # Return the decrypted and parsed data
    
    # Search and filter functions
    def filter_treeview(self, event=None):
        search_term = self.search_entry.get().lower()
        
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Filter and repopulate treeview
        for entry in self.passwords_db:
            website_match = search_term in entry['website'].lower()
            username_match = search_term in entry['username'].lower()
            
            if search_term == "" or website_match or username_match:
                strength = self.calculate_password_strength(entry['password'])
                strength_label = self.get_strength_label(strength)
                self.tree.insert('', 'end', values=(
                    entry['website'],
                    entry['username'],
                    '*' * len(entry['password']),
                    entry['timestamp'],
                    '👁️',
                    strength_label
                ))

    def clear_search(self):
        """Clear the search box and reset the treeview to show all entries"""
        self.search_entry.delete(0, tk.END)
        self.filter_treeview()
    
    # Session timeout handling
    def update_session_timer(self):
        now = time.time()
        elapsed = now - self.last_activity_time
        remaining = max(0, 290 - int(elapsed))  # 5 minutes = 300 seconds

        mins, secs = divmod(remaining, 60)
        self.master.title(f"BareReader - Session timeout in: {mins:02}:{secs:02}")

        if remaining <= 0:
            self.master.title("BareReader - Session expired")
            return

        self.master.after(1000, self.update_session_timer)

    def reset_activity_timer(self, event=None):
        self.last_activity_time = time.time()

    def update_title(self):
        elapsed_time = time.time() - self.last_activity_time
        remaining_time = self.timeout_seconds - elapsed_time

        if remaining_time <= 0:
            self.master.title("Session Expired!")
            return
        
        minutes, seconds = divmod(int(remaining_time), 60)
        time_str = f"Session time remaining: {minutes}m {seconds}s"
        self.master.title(f"Bare Password Manager - {time_str}")
        
        # Call this method again after 1 second (1000 ms)
        self.master.after(1000, self.update_title)

    def check_inactivity(self):
        elapsed_time = time.time() - self.last_activity_time
        if elapsed_time > self.timeout_seconds:
            messagebox.showwarning("Session Timeout", "Session expired due to inactivity.")
            self.logout()  # Logout when timeout is reached
        else:
            # Call check_inactivity again in 10 seconds to check for timeout
            self.master.after(10000, self.check_inactivity)
    
    # Password Strength Calculation
    def calculate_password_strength(self, password):
        strength = 0
        if len(password) >= 12:
            strength += 25
        if re.search(r"[A-Z]", password):
            strength += 25
        if re.search(r"[a-z]", password):
            strength += 25
        if re.search(r"\d", password):
            strength += 15
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            strength += 10
        return strength
    
    def get_strength_label(self, strength):
        if strength < 30:
            return "🔴 Weak"
        elif strength < 70:
            return "🟠 Medium"
        else:
            return "🟢 Strong"

    # Logout function
    def logout(self):
        self.passwords_db.clear()
        self.clear_widgets()
        self.key = None
        self.master_password = None
        self.prompt_for_login()

root = tk.Tk()
app = BarePasswordManager(root)
root.mainloop()
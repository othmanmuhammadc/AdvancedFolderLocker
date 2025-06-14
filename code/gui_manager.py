import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import threading
import json
import os
import sys
from pathlib import Path


def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


class ModernGUI:
    def __init__(self, encryption_manager, config):
        self.encryption_manager = encryption_manager
        self.config = config
        self.root = tk.Tk()
        self.setup_ui()
        self.setup_styles()

    def setup_styles(self):
        """Setup colors and styles"""
        style = ttk.Style()
        style.theme_use('clam')

        # Custom colors
        style.configure('Title.TLabel',
                        font=('Arial', 16, 'bold'),
                        foreground='#2c3e50')

        style.configure('Custom.TButton',
                        font=('Arial', 10),
                        padding=10)

    def setup_ui(self):
        """Setup user interface"""
        self.root.title("Advanced Folder Locker - Secure Your Folders")
        self.root.geometry("650x550")
        self.root.configure(bg='#ecf0f1')

        # Prevent resizing
        self.root.resizable(False, False)

        # FIXED: Proper icon loading with multiple fallback options
        self.set_window_icon()

        self.create_widgets()

    def set_window_icon(self):
        """Set window icon with proper fallback handling"""
        icon_paths = [
            get_resource_path('assets/icon.ico'),  # PyInstaller bundled
            'assets/icon.ico',  # Development
            get_resource_path('assets/icon.png'),  # PNG fallback
            'assets/icon.png',  # PNG fallback dev
            'icon.ico',  # Root directory fallback
            'icon.png'  # Root PNG fallback
        ]

        for icon_path in icon_paths:
            try:
                if os.path.exists(icon_path):
                    if icon_path.endswith('.ico'):
                        self.root.iconbitmap(icon_path)
                        print(f"✅ Icon loaded successfully: {icon_path}")
                        return
                    elif icon_path.endswith('.png'):
                        # For PNG files, we need to convert to PhotoImage
                        img = tk.PhotoImage(file=icon_path)
                        self.root.iconphoto(True, img)
                        print(f"✅ PNG Icon loaded successfully: {icon_path}")
                        return
            except Exception as e:
                print(f"❌ Failed to load icon {icon_path}: {e}")
                continue

        print("⚠️ No icon could be loaded - using default")

    def create_widgets(self):
        """Create UI elements"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="🔒 Advanced Folder Locker",
                                style='Title.TLabel')
        title_label.pack(pady=(0, 20))

        # Subtitle
        subtitle_label = ttk.Label(main_frame,
                                   text="Secure your folders with military-grade encryption",
                                   font=('Arial', 10), foreground='#7f8c8d')
        subtitle_label.pack(pady=(0, 25))

        # Main operations frame
        buttons_frame = ttk.LabelFrame(main_frame, text="Main Operations", padding="15")
        buttons_frame.pack(fill=tk.X, pady=(0, 15))

        # Operation buttons
        ttk.Button(buttons_frame, text="🔐 Lock Folder",
                   command=self.encrypt_folder_gui,
                   style='Custom.TButton').pack(pady=5, fill=tk.X)

        ttk.Button(buttons_frame, text="🔓 Unlock Folder",
                   command=self.decrypt_folder_gui,
                   style='Custom.TButton').pack(pady=5, fill=tk.X)

        ttk.Button(buttons_frame, text="📋 View Locked Folders",
                   command=self.show_locked_folders,
                   style='Custom.TButton').pack(pady=5, fill=tk.X)

        ttk.Button(buttons_frame, text="🗑️ Clear All Saved Passwords",
                   command=self.clear_saved_passwords,
                   style='Custom.TButton').pack(pady=5, fill=tk.X)

        # Information frame
        info_frame = ttk.LabelFrame(main_frame, text="Activity Log & Information", padding="10")
        info_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # Information display area
        self.info_text = ScrolledText(info_frame, height=12, width=75,
                                      font=('Consolas', 9))
        self.info_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var,
                               relief=tk.SUNKEN, padding="5")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Add initial information
        self.add_info("Welcome to Advanced Folder Locker!")
        self.add_info("You can now lock and unlock your folders with complete security")
        self.add_info("All passwords are stored encrypted and safe")
        self.add_info("Encryption: AES-256 with PBKDF2 (100,000 iterations)")

    def add_info(self, message):
        """Add message to information area"""
        self.info_text.insert(tk.END, f"[{self.get_timestamp()}] {message}\n")
        self.info_text.see(tk.END)
        self.root.update_idletasks()

    def get_timestamp(self):
        """Get current time"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")

    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()

    def encrypt_folder_gui(self):
        """Folder encryption interface"""
        folder_path = filedialog.askdirectory(title="Select folder to lock")
        if not folder_path:
            return

        # Check if folder has files
        folder = Path(folder_path)
        if not any(folder.iterdir()):
            messagebox.showwarning("Warning", "The selected folder is empty!")
            return

        # Request password
        password_dialog = PasswordDialog(self.root, "Enter Password",
                                         "Enter a strong password to lock the folder:")
        password = password_dialog.get_password()

        if not password:
            return

        if len(password) < 6:
            messagebox.showwarning("Warning", "Password must be at least 6 characters long")
            return

        # Confirm password
        confirm_dialog = PasswordDialog(self.root, "Confirm Password",
                                        "Re-enter the password to confirm:")
        confirm_password = confirm_dialog.get_password()

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        # Encrypt folder in separate thread
        self.run_in_thread(self._encrypt_folder_thread, folder_path, password)

    def _encrypt_folder_thread(self, folder_path, password):
        """Folder encryption thread"""
        try:
            # Update UI safely
            self.root.after(0, lambda: self.update_status("Encrypting folder..."))
            self.root.after(0, lambda: self.add_info(f"Starting encryption of folder: {Path(folder_path).name}"))

            # Perform encryption
            encrypted_file = self.encryption_manager.encrypt_folder(folder_path, password)
            folder_name = Path(folder_path).name

            # Save password
            password_hash = self.encryption_manager.hash_password(password)
            self.config.save_password(folder_name, password_hash)

            # Update UI on success
            self.root.after(0, lambda: self.add_info(f"Folder encrypted successfully: {folder_name}"))
            self.root.after(0, lambda: self.update_status("Encryption completed successfully"))
            self.root.after(0, lambda: messagebox.showinfo("Success",
                                                           f"Folder '{folder_name}' has been locked successfully!"))

        except Exception as e:
            # Only show error if encryption actually failed
            error_msg = str(e)
            self.root.after(0, lambda: self.add_info(f"Folder encryption failed: {error_msg}"))
            self.root.after(0, lambda: self.update_status("Encryption failed"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to lock folder:\n{error_msg}"))

    def decrypt_folder_gui(self):
        """Folder decryption interface"""
        file_types = [("Locked Folders", "*.locked"), ("All Files", "*.*")]
        encrypted_file = filedialog.askopenfilename(
            title="Select locked file",
            filetypes=file_types
        )

        if not encrypted_file:
            return

        folder_name = Path(encrypted_file).stem
        stored_hash = self.config.get_password_hash(folder_name)

        # Request password
        password_dialog = PasswordDialog(self.root, "Enter Password",
                                         f"Enter password to unlock '{folder_name}':")
        password = password_dialog.get_password()

        if not password:
            return

        # Verify password if stored (but don't fail if verification fails - let decryption handle it)
        if stored_hash and not self.encryption_manager.verify_password(password, stored_hash):
            messagebox.showwarning("Warning", "Password doesn't match stored hash. Attempting decryption anyway...")

        # Decrypt in separate thread
        self.run_in_thread(self._decrypt_folder_thread, encrypted_file, password, folder_name)

    def _decrypt_folder_thread(self, encrypted_file, password, folder_name):
        """Folder decryption thread"""
        try:
            # Update UI safely
            self.root.after(0, lambda: self.update_status("Unlocking folder..."))
            self.root.after(0, lambda: self.add_info(f"Starting decryption of folder: {folder_name}"))

            # Perform decryption
            restored_folder = self.encryption_manager.decrypt_folder(encrypted_file, password)

            # Remove saved password
            self.config.remove_password(folder_name)

            # Update UI on success
            self.root.after(0, lambda: self.add_info(f"Folder unlocked successfully: {Path(restored_folder).name}"))
            self.root.after(0, lambda: self.update_status("Unlock completed successfully"))
            self.root.after(0, lambda: messagebox.showinfo("Success",
                                                           f"Folder unlocked successfully!\nLocation: {restored_folder}"))

        except Exception as e:
            # Only show error if decryption actually failed
            error_msg = str(e)
            self.root.after(0, lambda: self.add_info(f"Folder unlock failed: {error_msg}"))
            self.root.after(0, lambda: self.update_status("Unlock failed"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to unlock folder:\n{error_msg}"))

    def show_locked_folders(self):
        """Display locked folders"""
        passwords = self.config.load_passwords()

        if not passwords:
            messagebox.showinfo("Information", "No locked folders found")
            return

        # Locked folders display window
        folders_window = tk.Toplevel(self.root)
        folders_window.title("Locked Folders")
        folders_window.geometry("450x350")
        folders_window.grab_set()

        # Folders list
        frame = ttk.Frame(folders_window, padding="15")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Currently Locked Folders:",
                  font=('Arial', 12, 'bold')).pack(pady=(0, 15))

        # Create treeview for better display
        tree = ttk.Treeview(frame, columns=('Status',), show='tree headings', height=12)
        tree.heading('#0', text='Folder Name')
        tree.heading('Status', text='Status')
        tree.column('#0', width=300)
        tree.column('Status', width=100)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        for folder_name in passwords.keys():
            tree.insert('', tk.END, text=f"🔒 {folder_name}", values=('Locked',))

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Close button
        ttk.Button(frame, text="Close",
                   command=folders_window.destroy).pack(pady=(15, 0))

    def clear_saved_passwords(self):
        """Clear all saved passwords"""
        passwords = self.config.load_passwords()

        if not passwords:
            messagebox.showinfo("Information", "No saved passwords to clear")
            return

        result = messagebox.askyesno("Confirm",
                                     f"Are you sure you want to clear all {len(passwords)} saved passwords?\n\n"
                                     "This action cannot be undone!")

        if result:
            # Clear passwords file
            try:
                with open(self.config.passwords_file, 'w') as f:
                    json.dump({}, f)

                self.add_info(f"Cleared {len(passwords)} saved passwords")
                messagebox.showinfo("Success", "All saved passwords have been cleared")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear passwords: {str(e)}")

    def run_in_thread(self, target, *args):
        """Run function in separate thread"""
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()

    def run(self):
        """Run application"""
        self.root.mainloop()


class PasswordDialog:
    def __init__(self, parent, title, prompt):
        self.result = None

        # Create window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x180")
        self.dialog.resizable(False, False)
        self.dialog.grab_set()

        # FIXED: Set icon for password dialog too
        try:
            # Try to use the same icon as parent window
            self.dialog.iconbitmap(parent.tk.call('wm', 'iconbitmap', parent))
        except:
            # Fallback to setting icon manually
            icon_paths = ['assets/icon.ico', 'icon.ico']
            for icon_path in icon_paths:
                try:
                    if os.path.exists(icon_path):
                        self.dialog.iconbitmap(icon_path)
                        break
                except:
                    continue

        # Center window
        self.dialog.transient(parent)
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 200
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 90
        self.dialog.geometry(f"+{x}+{y}")

        # Window content
        frame = ttk.Frame(self.dialog, padding="25")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=prompt, wraplength=350,
                  font=('Arial', 10)).pack(pady=(0, 20))

        self.entry = ttk.Entry(frame, show='*', font=('Arial', 12), width=35)
        self.entry.pack(pady=(0, 20))
        self.entry.focus()

        # Buttons
        buttons_frame = ttk.Frame(frame)
        buttons_frame.pack(fill=tk.X)

        ttk.Button(buttons_frame, text="OK",
                   command=self.ok_clicked).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(buttons_frame, text="Cancel",
                   command=self.cancel_clicked).pack(side=tk.RIGHT)

        # Bind Enter to OK
        self.dialog.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())

    def ok_clicked(self):
        self.result = self.entry.get()
        self.dialog.destroy()

    def cancel_clicked(self):
        self.result = None
        self.dialog.destroy()

    def get_password(self):
        self.dialog.wait_window()
        return self.result







    
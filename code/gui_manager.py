# code/gui_manager.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import threading
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any


def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


class ModernGUI:
    """Enhanced GUI with modern design and improved functionality"""

    def __init__(self, encryption_manager, config):
        self.encryption_manager = encryption_manager
        self.config = config
        self.root = tk.Tk()
        self.is_processing = False
        self.current_operation = None

        # Theme colors
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#3498db',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'light': '#ecf0f1',
            'dark': '#34495e',
            'text': '#2c3e50',
            'muted': '#7f8c8d'
        }

        self.setup_ui()
        self.setup_styles()
        self.setup_keyboard_shortcuts()
        self.load_window_state()

    def setup_styles(self):
        """Setup modern styles and themes"""
        style = ttk.Style()

        # Use modern theme
        available_themes = style.theme_names()
        if 'vista' in available_themes:
            style.theme_use('vista')
        elif 'clam' in available_themes:
            style.theme_use('clam')
        else:
            style.theme_use('default')

        # Configure custom styles
        style.configure('Title.TLabel',
                        font=('Segoe UI', 18, 'bold'),
                        foreground=self.colors['primary'])

        style.configure('Subtitle.TLabel',
                        font=('Segoe UI', 10),
                        foreground=self.colors['muted'])

        style.configure('Custom.TButton',
                        font=('Segoe UI', 10),
                        padding=(15, 10))

        style.configure('Action.TButton',
                        font=('Segoe UI', 10, 'bold'),
                        padding=(20, 12))

        style.configure('Success.TLabel',
                        font=('Segoe UI', 9),
                        foreground=self.colors['success'])

        style.configure('Warning.TLabel',
                        font=('Segoe UI', 9),
                        foreground=self.colors['warning'])

        style.configure('Error.TLabel',
                        font=('Segoe UI', 9),
                        foreground=self.colors['danger'])

    def setup_ui(self):
        """Setup enhanced user interface"""
        self.root.title("Advanced Folder Locker v2.0 - Secure Your Folders")
        self.root.geometry("750x650")
        self.root.configure(bg=self.colors['light'])
        self.root.minsize(650, 550)

        # Set window icon
        self.set_window_icon()

        # Configure window close protocol
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.create_menu()
        self.create_widgets()

        # Center window on screen
        self.center_window()

    def set_window_icon(self):
        """Set window icon with comprehensive fallback handling"""
        icon_paths = [
            get_resource_path('assets/icon.ico'),
            os.path.join('assets', 'icon.ico'),
            os.path.join('code', 'assets', 'icon.ico'),
            get_resource_path('assets/icon.png'),
            os.path.join('assets', 'icon.png'),
            'icon.ico',
            'icon.png'
        ]

        for icon_path in icon_paths:
            try:
                if os.path.exists(icon_path):
                    if icon_path.lower().endswith('.ico'):
                        self.root.iconbitmap(icon_path)
                        print(f"✅ Icon loaded: {icon_path}")
                        return
                    elif icon_path.lower().endswith('.png'):
                        img = tk.PhotoImage(file=icon_path)
                        self.root.iconphoto(True, img)
                        print(f"✅ PNG Icon loaded: {icon_path}")
                        return
            except Exception as e:
                print(f"❌ Icon load failed {icon_path}: {e}")
                continue

        print("⚠️ Using default icon")

    def create_menu(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Lock Folder", command=self.encrypt_folder_gui, accelerator="Ctrl+L")
        file_menu.add_command(label="Unlock Folder", command=self.decrypt_folder_gui, accelerator="Ctrl+U")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing, accelerator="Ctrl+Q")

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="View Locked Folders", command=self.show_locked_folders)
        tools_menu.add_command(label="Password Manager", command=self.show_password_manager)
        tools_menu.add_command(label="Activity History", command=self.show_activity_history)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings", command=self.show_settings)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Help", command=self.show_help)

    def create_widgets(self):
        """Create enhanced UI elements"""
        # Main container with padding
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header section
        self.create_header(main_container)

        # Main content area
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Left panel - Operations
        self.create_operations_panel(content_frame)

        # Right panel - Information
        self.create_info_panel(content_frame)

        # Bottom status bar
        self.create_status_bar(main_container)

        # Progress bar (hidden by default)
        self.create_progress_bar(main_container)

    def create_header(self, parent):
        """Create application header"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 25))

        # Title and subtitle
        title_label = ttk.Label(header_frame, text="🔒 Advanced Folder Locker",
                                style='Title.TLabel')
        title_label.pack()

        subtitle_label = ttk.Label(header_frame,
                                   text="Military-grade AES-256 encryption with PBKDF2 key derivation",
                                   style='Subtitle.TLabel')
        subtitle_label.pack(pady=(5, 0))

        # Quick stats
        self.create_stats_panel(header_frame)

    def create_stats_panel(self, parent):
        """Create quick statistics panel"""
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill=tk.X, pady=(15, 0))

        # Get current stats
        stats = self.config.get_stats()

        # Stats labels
        stats_container = ttk.Frame(stats_frame)
        stats_container.pack()

        ttk.Label(stats_container, text=f"📁 Locked Folders: {stats['locked_folders']}",
                  font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 20))

        ttk.Label(stats_container, text=f"🔄 Total Operations: {stats['total_operations']}",
                  font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 20))

        if stats['last_used']:
            try:
                last_used = datetime.fromisoformat(stats['last_used'])
                last_used_str = last_used.strftime("%Y-%m-%d %H:%M")
                ttk.Label(stats_container, text=f"🕐 Last Used: {last_used_str}",
                          font=('Segoe UI', 9)).pack(side=tk.LEFT)
            except:
                pass

    def create_operations_panel(self, parent):
        """Create operations panel"""
        operations_frame = ttk.LabelFrame(parent, text="🛠️ Main Operations", padding="20")
        operations_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        # Main action buttons
        btn_frame = ttk.Frame(operations_frame)
        btn_frame.pack(fill=tk.X)

        self.lock_btn = ttk.Button(btn_frame, text="🔐 Lock Folder",
                                   command=self.encrypt_folder_gui,
                                   style='Action.TButton')
        self.lock_btn.pack(fill=tk.X, pady=(0, 10))

        self.unlock_btn = ttk.Button(btn_frame, text="🔓 Unlock Folder",
                                     command=self.decrypt_folder_gui,
                                     style='Action.TButton')
        self.unlock_btn.pack(fill=tk.X, pady=(0, 15))

        # Separator
        ttk.Separator(btn_frame, orient='horizontal').pack(fill=tk.X, pady=(0, 15))

        # Secondary operations
        ttk.Button(btn_frame, text="📋 View Locked Folders",
                   command=self.show_locked_folders,
                   style='Custom.TButton').pack(fill=tk.X, pady=(0, 8))

        ttk.Button(btn_frame, text="🔑 Password Manager",
                   command=self.show_password_manager,
                   style='Custom.TButton').pack(fill=tk.X, pady=(0, 8))

        ttk.Button(btn_frame, text="📊 Activity History",
                   command=self.show_activity_history,
                   style='Custom.TButton').pack(fill=tk.X, pady=(0, 8))

        ttk.Button(btn_frame, text="🧹 Clear All Data",
                   command=self.clear_all_data,
                   style='Custom.TButton').pack(fill=tk.X, pady=(0, 8))

        # Security info
        security_frame = ttk.LabelFrame(operations_frame, text="🔐 Security Information", padding="10")
        security_frame.pack(fill=tk.X, pady=(20, 0))

        security_info = [
            "• AES-256 Encryption",
            "• PBKDF2 Key Derivation",
            "• 100,000 Iterations",
            "• Secure Salt Generation",
            "• Password Hashing"
        ]

        for info in security_info:
            ttk.Label(security_frame, text=info, font=('Segoe UI', 8),
                      foreground=self.colors['muted']).pack(anchor=tk.W)

    def create_info_panel(self, parent):
        """Create information panel"""
        info_frame = ttk.LabelFrame(parent, text="📝 Activity Log & Information", padding="15")
        info_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Log area
        self.info_text = ScrolledText(info_frame, height=20, width=50,
                                      font=('Consolas', 9), wrap=tk.WORD)
        self.info_text.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for colored output
        self.info_text.tag_configure("success", foreground=self.colors['success'])
        self.info_text.tag_configure("warning", foreground=self.colors['warning'])
        self.info_text.tag_configure("error", foreground=self.colors['danger'])
        self.info_text.tag_configure("info", foreground=self.colors['secondary'])

        # Log control buttons
        log_controls = ttk.Frame(info_frame)
        log_controls.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(log_controls, text="Clear Log",
                   command=self.clear_log).pack(side=tk.LEFT)

        ttk.Button(log_controls, text="Save Log",
                   command=self.save_log).pack(side=tk.LEFT, padx=(10, 0))

        # Add welcome messages
        self.add_welcome_messages()

    def create_status_bar(self, parent):
        """Create status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))

        self.status_var = tk.StringVar(value="Ready - Advanced Folder Locker v2.0")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                      relief=tk.SUNKEN, padding="5")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Operation indicator
        self.operation_var = tk.StringVar(value="")
        self.operation_label = ttk.Label(status_frame, textvariable=self.operation_var,
                                         font=('Segoe UI', 8), foreground=self.colors['secondary'])
        self.operation_label.pack(side=tk.RIGHT, padx=(10, 0))

    def create_progress_bar(self, parent):
        """Create progress bar"""
        self.progress_frame = ttk.Frame(parent)
        self.progress_frame.pack(fill=tk.X, pady=(5, 0))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var,
                                            mode='indeterminate')
        self.progress_bar.pack(fill=tk.X)

        # Hide progress bar initially
        self.progress_frame.pack_forget()

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.root.bind('<Control-l>', lambda e: self.encrypt_folder_gui())
        self.root.bind('<Control-u>', lambda e: self.decrypt_folder_gui())
        self.root.bind('<Control-q>', lambda e: self.on_closing())
        self.root.bind('<F1>', lambda e: self.show_help())
        self.root.bind('<F5>', lambda e: self.refresh_stats())

    def add_welcome_messages(self):
        """Add welcome messages to log"""
        welcome_messages = [
            ("Welcome to Advanced Folder Locker v2.0! 🎉", "success"),
            ("Enhanced security with military-grade encryption", "info"),
            ("All passwords are securely hashed and stored", "info"),
            ("Use Ctrl+L to lock folders, Ctrl+U to unlock", "info"),
            ("Ready to secure your folders! 🔒", "success")
        ]

        for message, tag in welcome_messages:
            self.add_info(message, tag)

    def add_info(self, message: str, tag: str = "info"):
        """Add message to information area with timestamp and styling"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"

        self.info_text.insert(tk.END, formatted_message, tag)
        self.info_text.see(tk.END)
        self.root.update_idletasks()

    def update_status(self, message: str, operation: str = ""):
        """Update status bar with operation indicator"""
        self.status_var.set(message)
        self.operation_var.set(operation)
        self.root.update_idletasks()

    def show_progress(self, show: bool = True):
        """Show or hide progress bar"""
        if show:
            self.progress_frame.pack(fill=tk.X, pady=(5, 0))
            self.progress_bar.start(10)
        else:
            self.progress_bar.stop()
            self.progress_frame.pack_forget()

    def set_processing_state(self, processing: bool, operation: str = ""):
        """Set processing state and update UI accordingly"""
        self.is_processing = processing
        self.current_operation = operation if processing else None

        # Update button states
        state = tk.DISABLED if processing else tk.NORMAL
        self.lock_btn.config(state=state)
        self.unlock_btn.config(state=state)

        # Show/hide progress bar
        self.show_progress(processing)

        if processing:
            self.update_status(f"Processing... {operation}", "⏳")
        else:
            self.update_status("Ready", "")

    def encrypt_folder_gui(self):
        """Enhanced folder encryption interface"""
        if self.is_processing:
            messagebox.showwarning("Warning", "Another operation is in progress. Please wait...")
            return

        folder_path = filedialog.askdirectory(title="Select folder to lock")
        if not folder_path:
            return

        folder = Path(folder_path)

        # Enhanced folder validation
        if not folder.exists():
            messagebox.showerror("Error", "Selected folder does not exist!")
            return

        if not folder.is_dir():
            messagebox.showerror("Error", "Selected path is not a directory!")
            return

        # Check if folder has files
        files = list(folder.rglob('*'))
        file_count = sum(1 for f in files if f.is_file())

        if file_count == 0:
            messagebox.showwarning("Warning", "The selected folder is empty!")
            return

        # Check if folder is already locked
        locked_file = folder.with_suffix('.locked')
        if locked_file.exists():
            messagebox.showwarning("Warning", "This folder appears to be already locked!")
            return

        # Show folder info
        folder_size = sum(f.stat().st_size for f in files if f.is_file())
        size_mb = folder_size / (1024 * 1024)

        folder_info = f"Folder: {folder.name}\nFiles: {file_count}\nSize: {size_mb:.2f} MB"

        if not messagebox.askyesno("Confirm Lock", f"Lock this folder?\n\n{folder_info}"):
            return

        # Enhanced password dialog
        password_dialog = EnhancedPasswordDialog(
            self.root,
            "Create Password",
            f"Create a strong password to lock '{folder.name}':",
            show_strength=True
        )
        password = password_dialog.get_password()

        if not password:
            return

        # Validate password strength
        is_strong, strength_msg = self.encryption_manager.validate_password_strength(password)
        if not is_strong:
            if not messagebox.askyesno("Weak Password", f"{strength_msg}\n\nContinue anyway?"):
                return

        # Confirm password
        confirm_dialog = EnhancedPasswordDialog(
            self.root,
            "Confirm Password",
            "Re-enter the password to confirm:"
        )
        confirm_password = confirm_dialog.get_password()

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        # Encrypt in thread
        self.run_in_thread(self._encrypt_folder_thread, folder_path, password)

    def _encrypt_folder_thread(self, folder_path: str, password: str):
        """Enhanced folder encryption thread"""
        try:
            folder_name = Path(folder_path).name

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(True, "Encrypting folder..."))
            self.root.after(0, lambda: self.add_info(f"🔄 Starting encryption: {folder_name}", "info"))

            # Perform encryption
            encrypted_file = self.encryption_manager.encrypt_folder(folder_path, password)

            # Save password hash
            password_hash = self.encryption_manager.hash_password(password)
            self.config.save_password(folder_name, password_hash, encrypted_file)

            # Add to history
            self.config.add_to_history("encrypt", folder_name, "success")

            # Update UI on success
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_info(f"✅ Folder encrypted successfully: {folder_name}", "success"))
            self.root.after(0, lambda: self.refresh_stats())
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"Folder '{folder_name}' has been locked successfully!\n\n"
                f"Encrypted file: {Path(encrypted_file).name}"
            ))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_info(f"❌ Encryption failed: {error_msg}", "error"))
            self.root.after(0,
                            lambda: messagebox.showerror("Encryption Failed", f"Failed to lock folder:\n\n{error_msg}"))

            # Add to history
            try:
                folder_name = Path(folder_path).name
                self.config.add_to_history("encrypt", folder_name, "failed")
            except:
                pass

    def decrypt_folder_gui(self):
        """Enhanced folder decryption interface"""
        if self.is_processing:
            messagebox.showwarning("Warning", "Another operation is in progress. Please wait...")
            return

        file_types = [("Locked Folders", "*.locked"), ("All Files", "*.*")]
        encrypted_file = filedialog.askopenfilename(
            title="Select locked file to unlock",
            filetypes=file_types
        )

        if not encrypted_file:
            return

        encrypted_path = Path(encrypted_file)
        folder_name = encrypted_path.stem

        # Get file info
        file_info = self.encryption_manager.get_file_info(encrypted_file)
        if "error" in file_info:
            messagebox.showerror("Error", f"Cannot read file: {file_info['error']}")
            return

        # Show file info
        size_mb = file_info['size'] / (1024 * 1024)
        info_text = f"File: {file_info['filename']}\nSize: {size_mb:.2f} MB\nVersion: {file_info['version']}"

        if not messagebox.askyesno("Confirm Unlock", f"Unlock this folder?\n\n{info_text}"):
            return

        # Get stored password hash
        stored_hash = self.config.get_password_hash(folder_name)

        # Password dialog
        password_dialog = EnhancedPasswordDialog(
            self.root,
            "Enter Password",
            f"Enter password to unlock '{folder_name}':"
        )
        password = password_dialog.get_password()

        if not password:
            return

        # Verify password if stored
        if stored_hash and not self.encryption_manager.verify_password(password, stored_hash):
            if not messagebox.askyesno("Password Warning",
                                       "Password doesn't match stored hash. This may be due to:\n"
                                       "• Incorrect password\n"
                                       "• Different password used\n"
                                       "• Corrupted password data\n\n"
                                       "Attempt decryption anyway?"):
                return

        # Decrypt in thread
        self.run_in_thread(self._decrypt_folder_thread, encrypted_file, password, folder_name)

    def _decrypt_folder_thread(self, encrypted_file: str, password: str, folder_name: str):
        """Enhanced folder decryption thread"""
        try:
            # Update UI
            self.root.after(0, lambda: self.set_processing_state(True, "Decrypting folder..."))
            self.root.after(0, lambda: self.add_info(f"🔄 Starting decryption: {folder_name}", "info"))

            # Perform decryption
            restored_folder = self.encryption_manager.decrypt_folder(encrypted_file, password)

            # Remove saved password
            self.config.remove_password(folder_name)

            # Add to history
            self.config.add_to_history("decrypt", folder_name, "success")

            # Update UI on success
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_info(f"✅ Folder unlocked successfully: {Path(restored_folder).name}",
                                                     "success"))
            self.root.after(0, lambda: self.refresh_stats())
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"Folder unlocked successfully!\n\n"
                f"Location: {restored_folder}"
            ))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_info(f"❌ Decryption failed: {error_msg}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Decryption Failed",
                                                            f"Failed to unlock folder:\n\n{error_msg}"))

            # Add to history
            try:
                self.config.add_to_history("decrypt", folder_name, "failed")
            except:
                pass

    def show_locked_folders(self):
        """Enhanced locked folders display"""
        passwords = self.config.load_passwords()

        if not passwords:
            messagebox.showinfo("Information", "No locked folders found")
            return

        # Create modern folders window
        folders_window = tk.Toplevel(self.root)
        folders_window.title("Locked Folders Manager")
        folders_window.geometry("600x400")
        folders_window.grab_set()
        folders_window.resizable(True, True)

        # Set icon
        try:
            folders_window.iconbitmap(self.root.tk.call('wm', 'iconbitmap', self.root))
        except:
            pass

        # Main frame
        main_frame = ttk.Frame(folders_window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(header_frame, text="🔒 Locked Folders Manager",
                  font=('Segoe UI', 14, 'bold')).pack(side=tk.LEFT)

        ttk.Label(header_frame, text=f"Total: {len(passwords)} folders",
                  font=('Segoe UI', 10)).pack(side=tk.RIGHT)

        # Treeview with detailed information
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        columns = ('Size', 'Created', 'Access Count')
        tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings', height=15)

        # Configure columns
        tree.heading('#0', text='Folder Name')
        tree.heading('Size', text='Size')
        tree.heading('Created', text='Created')
        tree.heading('Access Count', text='Access Count')

        tree.column('#0', width=250)
        tree.column('Size', width=100)
        tree.column('Created', width=150)
        tree.column('Access Count', width=100)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # Populate tree
        for folder_name, data in passwords.items():
            if isinstance(data, dict):
                # Try to get file info
                file_path = data.get('file_path')
                size_str = "Unknown"
                if file_path and os.path.exists(file_path):
                    try:
                        size = os.path.getsize(file_path)
                        size_str = f"{size / (1024 * 1024):.1f} MB"
                    except:
                        pass

                created = data.get('created', 'Unknown')
                if created != 'Unknown':
                    try:
                        created_dt = datetime.fromisoformat(created)
                        created = created_dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        pass

                access_count =



                
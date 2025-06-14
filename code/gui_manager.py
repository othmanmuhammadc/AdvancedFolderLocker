# code/gui_manager.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText
import threading
import json
import os
import sys
import time
import webbrowser
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


class EnhancedPasswordDialog:
    """Enhanced password dialog with strength indicator"""

    def __init__(self, parent, title, message, show_strength=False):
        self.result = None
        self.show_strength = show_strength

        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x300" if show_strength else "400x200")
        self.dialog.resizable(False, False)
        self.dialog.grab_set()
        self.dialog.transient(parent)

        # Center on parent
        self.center_on_parent(parent)

        # Create widgets
        self.create_widgets(message)

        # Focus on password entry
        self.password_entry.focus_set()

        # Bind events
        self.dialog.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())

    def center_on_parent(self, parent):
        """Center dialog on parent window"""
        parent.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 200
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 100
        self.dialog.geometry(f"+{x}+{y}")

    def create_widgets(self, message):
        """Create dialog widgets"""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Message label
        ttk.Label(main_frame, text=message, font=('Segoe UI', 10)).pack(pady=(0, 15))

        # Password frame
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(password_frame, text="Password:").pack(anchor=tk.W)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var,
                                        show="*", font=('Segoe UI', 10))
        self.password_entry.pack(fill=tk.X, pady=(5, 0))

        # Show/hide password toggle
        self.show_password_var = tk.BooleanVar()
        show_password_cb = ttk.Checkbutton(password_frame, text="Show password",
                                           variable=self.show_password_var,
                                           command=self.toggle_password_visibility)
        show_password_cb.pack(anchor=tk.W, pady=(5, 0))

        # Password strength indicator (if enabled)
        if self.show_strength:
            self.create_strength_indicator(main_frame)

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))

        ttk.Button(button_frame, text="Cancel", command=self.cancel_clicked).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="OK", command=self.ok_clicked).pack(side=tk.RIGHT, padx=(0, 10))

    def create_strength_indicator(self, parent):
        """Create password strength indicator"""
        strength_frame = ttk.LabelFrame(parent, text="Password Strength", padding="10")
        strength_frame.pack(fill=tk.X, pady=(10, 0))

        self.strength_var = tk.StringVar(value="Enter password to see strength")
        self.strength_label = ttk.Label(strength_frame, textvariable=self.strength_var)
        self.strength_label.pack()

        # Progress bar for strength
        self.strength_progress = ttk.Progressbar(strength_frame, length=300, mode='determinate')
        self.strength_progress.pack(fill=tk.X, pady=(5, 0))

        # Requirements checklist
        self.requirements_frame = ttk.Frame(strength_frame)
        self.requirements_frame.pack(fill=tk.X, pady=(10, 0))

        requirements = [
            "At least 8 characters",
            "Contains uppercase letter",
            "Contains lowercase letter",
            "Contains numbers",
            "Contains special characters"
        ]

        self.requirement_vars = []
        for req in requirements:
            var = tk.StringVar(value=f"❌ {req}")
            self.requirement_vars.append(var)
            ttk.Label(self.requirements_frame, textvariable=var, font=('Segoe UI', 8)).pack(anchor=tk.W)

        # Bind password change event
        self.password_var.trace('w', self.check_password_strength)

    def check_password_strength(self, *args):
        """Check and update password strength"""
        password = self.password_var.get()

        if not password:
            self.strength_var.set("Enter password to see strength")
            self.strength_progress['value'] = 0
            for i, var in enumerate(self.requirement_vars):
                requirements = [
                    "At least 8 characters",
                    "Contains uppercase letter",
                    "Contains lowercase letter",
                    "Contains numbers",
                    "Contains special characters"
                ]
                var.set(f"❌ {requirements[i]}")
            return

        # Check requirements
        checks = [
            len(password) >= 8,
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        ]

        requirements = [
            "At least 8 characters",
            "Contains uppercase letter",
            "Contains lowercase letter",
            "Contains numbers",
            "Contains special characters"
        ]

        # Update requirement labels
        for i, (check, var) in enumerate(zip(checks, self.requirement_vars)):
            symbol = "✅" if check else "❌"
            var.set(f"{symbol} {requirements[i]}")

        # Calculate strength
        strength = sum(checks)
        strength_percent = (strength / len(checks)) * 100
        self.strength_progress['value'] = strength_percent

        if strength <= 2:
            strength_text = "Weak"
            color = "red"
        elif strength <= 3:
            strength_text = "Fair"
            color = "orange"
        elif strength <= 4:
            strength_text = "Good"
            color = "blue"
        else:
            strength_text = "Strong"
            color = "green"

        self.strength_var.set(f"Password strength: {strength_text}")

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def ok_clicked(self):
        """Handle OK button click"""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password!")
            return

        self.result = password
        self.dialog.destroy()

    def cancel_clicked(self):
        """Handle Cancel button click"""
        self.result = None
        self.dialog.destroy()

    def get_password(self):
        """Get the entered password"""
        self.dialog.wait_window()
        return self.result


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

        # File dialog for encrypted files
        encrypted_file = filedialog.askopenfilename(
            title="Select encrypted folder file",
            filetypes=[("Locked Files", "*.locked"), ("All Files", "*.*")]
        )

        if not encrypted_file:
            return

        encrypted_path = Path(encrypted_file)

        # Validate file
        if not encrypted_path.exists():
            messagebox.showerror("Error", "Selected file does not exist!")
            return

        if not encrypted_path.is_file():
            messagebox.showerror("Error", "Selected path is not a file!")
            return

        # Get file info
        file_info = self.encryption_manager.get_file_info(encrypted_path)
        if "error" in file_info:
            messagebox.showerror("Error", f"Invalid encrypted file: {file_info['error']}")
            return

        # Show file info
        size_mb = file_info['size'] / (1024 * 1024)
        created_date = datetime.fromtimestamp(file_info['created']).strftime("%Y-%m-%d %H:%M")

        info_text = f"File: {file_info['filename']}\n"
        info_text += f"Folder: {file_info['folder_name']}\n"
        info_text += f"Size: {size_mb:.2f} MB\n"
        info_text += f"Created: {created_date}\n"
        info_text += f"Version: {file_info['version']}"

        if not messagebox.askyesno("Confirm Unlock", f"Unlock this folder?\n\n{info_text}"):
            return

        # Password dialog
        password_dialog = EnhancedPasswordDialog(
            self.root,
            "Enter Password",
            f"Enter password to unlock '{file_info['folder_name']}':"
        )
        password = password_dialog.get_password()

        if not password:
            return

        # Decrypt in thread
        self.run_in_thread(self._decrypt_folder_thread, encrypted_file, password)

    def _decrypt_folder_thread(self, encrypted_file: str, password: str):
        """Enhanced folder decryption thread"""
        try:
            folder_name = Path(encrypted_file).stem

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(True, "Decrypting folder..."))
            self.root.after(0, lambda: self.add_info(f"🔄 Starting decryption: {folder_name}", "info"))

            # Perform decryption
            decrypted_folder = self.encryption_manager.decrypt_folder(encrypted_file, password)

            # Remove password from storage
            self.config.remove_password(folder_name)

            # Add to history
            self.config.add_to_history("decrypt", folder_name, "success")

            # Update UI on success
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_info(f"✅ Folder decrypted successfully: {folder_name}", "success"))
            self.root.after(0, lambda: self.refresh_stats())
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"Folder '{folder_name}' has been unlocked successfully!\n\n"
                f"Restored to: {Path(decrypted_folder).name}"
            ))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_info(f"❌ Decryption failed: {error_msg}", "error"))
            self.root.after(0,
                            lambda: messagebox.showerror("Decryption Failed",
                                                         f"Failed to unlock folder:\n\n{error_msg}"))

            # Add to history
            try:
                folder_name = Path(encrypted_file).stem
                self.config.add_to_history("decrypt", folder_name, "failed")
            except:
                pass

    def show_locked_folders(self):
        """Show list of locked folders"""
        passwords = self.config.load_passwords()

        if not passwords:
            messagebox.showinfo("No Locked Folders", "No locked folders found.")
            return

        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Locked Folders")
        dialog.geometry("600x400")
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(main_frame, text="🔒 Locked Folders", font=('Segoe UI', 14, 'bold')).pack(pady=(0, 15))

        # Treeview for folders
        columns = ('Folder', 'Created', 'Access Count', 'File Path')
        tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=15)

        # Configure columns
        tree.heading('Folder', text='Folder Name')
        tree.heading('Created', text='Created')
        tree.heading('Access Count', text='Access Count')
        tree.heading('File Path', text='File Path')

        tree.column('Folder', width=150)
        tree.column('Created', width=120)
        tree.column('Access Count', width=100)
        tree.column('File Path', width=200)

        # Scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        # Pack treeview and scrollbar
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate data
        for folder_name, data in passwords.items():
            if isinstance(data, dict):
                created = data.get('created', 'Unknown')
                if created != 'Unknown':
                    try:
                        created_dt = datetime.fromisoformat(created)
                        created = created_dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        pass

                access_count = data.get('access_count', 0)
                file_path = data.get('file_path', 'Unknown')
                if file_path and len(file_path) > 50:
                    file_path = "..." + file_path[-47:]
            else:
                created = 'Unknown'
                access_count = 0
                file_path = 'Unknown'

            tree.insert('', tk.END, values=(folder_name, created, access_count, file_path))

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))

        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Refresh", command=lambda: self.refresh_locked_folders(tree)).pack(side=tk.RIGHT,
                                                                                                         padx=(0, 10))

    def show_password_manager(self):
        """Show password manager dialog"""
        passwords = self.config.load_passwords()

        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Manager")
        dialog.geometry("500x400")
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(main_frame, text="🔑 Password Manager", font=('Segoe UI', 14, 'bold')).pack(pady=(0, 15))

        if not passwords:
            ttk.Label(main_frame, text="No saved passwords found.", font=('Segoe UI', 10)).pack(pady=20)
            ttk.Button(main_frame, text="Close", command=dialog.destroy).pack()
            return

        # Listbox for folders
        listbox_frame = ttk.Frame(main_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        listbox = tk.Listbox(listbox_frame, font=('Segoe UI', 10))
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)

        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate listbox
        for folder_name in passwords.keys():
            listbox.insert(tk.END, folder_name)

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        def remove_selected():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a folder to remove.")
                return

            folder_name = listbox.get(selection[0])
            if messagebox.askyesno("Confirm Removal",
                                   f"Remove password for '{folder_name}'?\n\nThis will not affect the encrypted file."):
                self.config.remove_password(folder_name)
                listbox.delete(selection[0])
                self.add_info(f"🗑️ Password removed for: {folder_name}", "warning")

        ttk.Button(button_frame, text="Remove Selected", command=remove_selected).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)

    def show_activity_history(self):
        """Show activity history dialog"""
        history = self.config.load_history()

        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Activity History")
        dialog.geometry("700x500")
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(main_frame, text="📊 Activity History", font=('Segoe UI', 14, 'bold')).pack(pady=(0, 15))

        if not history:
            ttk.Label(main_frame, text="No activity history found.", font=('Segoe UI', 10)).pack(pady=20)
            ttk.Button(main_frame, text="Close", command=dialog.destroy).pack()
            return

        # Treeview for history
        columns = ('Time', 'Action', 'Folder', 'Status')
        tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20)

        # Configure columns
        tree.heading('Time', text='Timestamp')
        tree.heading('Action', text='Action')
        tree.heading('Folder', text='Folder Name')
        tree.heading('Status', text='Status')

        tree.column('Time', width=150)
        tree.column('Action', width=100)
        tree.column('Folder', width=200)
        tree.column('Status', width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        # Pack treeview and scrollbar
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate data (reverse order - newest first)
        for entry in reversed(history):
            timestamp = entry.get('timestamp', 'Unknown')
            if timestamp != 'Unknown':
                try:
                    dt = datetime.fromisoformat(timestamp)
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass

            action = entry.get('action', 'Unknown').title()
            folder_name = entry.get('folder_name', 'Unknown')
            status = entry.get('status', 'Unknown').title()

            # Add status emoji
            if status == 'Success':
                status = '✅ Success'
            elif status == 'Failed':
                status = '❌ Failed'

            tree.insert('', tk.END, values=(timestamp, action, folder_name, status))

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))

        def clear_history():
            if messagebox.askyesno("Clear History", "Clear all activity history?"):
                # Clear history by creating empty file
                with open(self.config.history_file, 'w') as f:
                    json.dump([], f)
                dialog.destroy()
                self.add_info("🧹 Activity history cleared", "warning")

        ttk.Button(button_frame, text="Clear History", command=clear_history).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)

    def show_settings(self):
        """Show settings dialog"""
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(main_frame, text="⚙️ Settings", font=('Segoe UI', 14, 'bold')).pack(pady=(0, 20))

        # Settings frame
        settings_frame = ttk.LabelFrame(main_frame, text="Application Settings", padding="15")
        settings_frame.pack(fill=tk.X, pady=(0, 15))

        # Auto hide files setting
        auto_hide_var = tk.BooleanVar(value=self.config.get_config_value('auto_hide_files', True))
        ttk.Checkbutton(settings_frame, text="Auto-hide encrypted files (Windows)",
                        variable=auto_hide_var).pack(anchor=tk.W, pady=(0, 10))

        # Theme setting
        theme_frame = ttk.Frame(settings_frame)
        theme_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(theme_frame, text="Theme:").pack(side=tk.LEFT)
        theme_var = tk.StringVar(value=self.config.get_config_value('theme', 'default'))
        theme_combo = ttk.Combobox(theme_frame, textvariable=theme_var,
                                   values=['default', 'dark', 'light'], state='readonly')
        theme_combo.pack(side=tk.LEFT, padx=(10, 0))

        # Log level setting
        log_frame = ttk.Frame(settings_frame)
        log_frame.pack(fill=tk.X)

        ttk.Label(log_frame, text="Log Level:").pack(side=tk.LEFT)
        log_var = tk.StringVar(value=self.config.get_config_value('log_level', 'INFO'))
        log_combo = ttk.Combobox(log_frame, textvariable=log_var,
                                 values=['DEBUG', 'INFO', 'WARNING', 'ERROR'], state='readonly')
        log_combo.pack(side=tk.LEFT, padx=(10, 0))

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        def save_settings():
            self.config.set_config_value('auto_hide_files', auto_hide_var.get())
            self.config.set_config_value('theme', theme_var.get())
            self.config.set_config_value('log_level', log_var.get())
            messagebox.showinfo("Settings Saved", "Settings have been saved successfully!")
            dialog.destroy()

        ttk.Button(button_frame, text="Save", command=save_settings).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 10))

    def show_about(self):
        """Show about dialog"""
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("About")
        dialog.geometry("450x400")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame
        main_frame = ttk.Frame(dialog, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Icon and title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(pady=(0, 20))

        ttk.Label(title_frame, text="🔒", font=('Segoe UI', 32)).pack()
        ttk.Label(title_frame, text="Advanced Folder Locker", font=('Segoe UI', 16, 'bold')).pack(pady=(10, 0))
        ttk.Label(title_frame, text="Version 2.0.0", font=('Segoe UI', 10)).pack()

        # Description
        desc_text = """Military-grade folder encryption with AES-256 encryption and PBKDF2 key derivation.

Features:
• AES-256 encryption with 100,000 PBKDF2 iterations
• Secure password hashing and storage
• Enhanced password strength validation
• Activity logging and history tracking
• Modern, user-friendly interface
• Cross-platform compatibility

Developed with security and usability in mind."""

        ttk.Label(main_frame, text=desc_text, font=('Segoe UI', 9), justify=tk.LEFT).pack(pady=(0, 20))

        # Links frame
        links_frame = ttk.Frame(main_frame)
        links_frame.pack(pady=(0, 20))

        def open_github():
            webbrowser.open("https://github.com/othmanmuhammadc/AdvancedFolderLocker")

        ttk.Button(links_frame, text="🌐 GitHub Repository", command=open_github).pack(pady=(0, 5))

        # Close button
        ttk.Button(main_frame, text="Close", command=dialog.destroy).pack()

    def show_help(self):
        """Show help dialog"""
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Help")
        dialog.geometry("600x500")
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(main_frame, text="❓ Help & Instructions", font=('Segoe UI', 14, 'bold')).pack(pady=(0, 15))

        # Help text
        help_text = ScrolledText(main_frame, height=25, width=70, font=('Segoe UI', 9), wrap=tk.WORD)
        help_text.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        help_content = """ADVANCED FOLDER LOCKER - HELP GUIDE

🔐 LOCKING FOLDERS:
1. Click "Lock Folder" or press Ctrl+L
2. Select the folder you want to encrypt
3. Create a strong password (recommended: 12+ characters with mixed case, numbers, and symbols)
4. Confirm your password
5. The folder will be encrypted and the original folder removed

🔓 UNLOCKING FOLDERS:
1. Click "Unlock Folder" or press Ctrl+U
2. Select the .locked file
3. Enter the correct password
4. The folder will be restored and the encrypted file removed

🔑 PASSWORD SECURITY:
• Use strong, unique passwords for each folder
• Passwords are hashed using PBKDF2 with 100,000 iterations
• Lost passwords cannot be recovered - keep them safe!
• Consider using a password manager

📋 MANAGING LOCKED FOLDERS:
• View all locked folders and their information
• Remove saved password hashes (doesn't affect encrypted files)
• Monitor access counts and creation dates

📊 ACTIVITY HISTORY:
• Track all encryption/decryption operations
• View timestamps and operation status
• Clear history when needed

⚙️ SETTINGS:
• Configure auto-hide for encrypted files (Windows)
• Adjust logging levels
• Customize application theme

🔒 SECURITY FEATURES:
• AES-256 encryption (military-grade)
• PBKDF2 key derivation with salt
• Secure random salt generation
• Password strength validation
• Encrypted file format with metadata

⌨️ KEYBOARD SHORTCUTS:
• Ctrl+L: Lock Folder
• Ctrl+U: Unlock Folder
• Ctrl+Q: Exit Application
• F1: Show Help
• F5: Refresh Statistics

⚠️ IMPORTANT NOTES:
• Always backup important data before encryption
• Keep passwords secure - they cannot be recovered
• Encrypted files are portable across systems
• Original folders are permanently deleted after encryption
• Ensure sufficient disk space for encryption process

🛠️ TROUBLESHOOTING:
• If encryption fails, check folder permissions and disk space
• For decryption issues, verify password and file integrity
• Check activity log for detailed error information
• Restart application if interface becomes unresponsive

For more information and updates, visit:
https://github.com/othmanmuhammadc/AdvancedFolderLocker"""

        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)

        # Close button
        ttk.Button(main_frame, text="Close", command=dialog.destroy).pack()

    def clear_all_data(self):
        """Clear all application data"""
        if not messagebox.askyesno("Clear All Data",
                                   "This will remove all saved passwords and history.\n\n"
                                   "Encrypted files will NOT be affected.\n\n"
                                   "Continue?"):
            return

        try:
            self.config.clear_all_data()
            self.add_info("🧹 All application data cleared", "warning")
            self.refresh_stats()
            messagebox.showinfo("Data Cleared", "All application data has been cleared successfully!")
        except Exception as e:
            error_msg = str(e)
            self.add_info(f"❌ Failed to clear data: {error_msg}", "error")
            messagebox.showerror("Error", f"Failed to clear data:\n\n{error_msg}")

    def clear_log(self):
        """Clear the activity log"""
        self.info_text.delete(1.0, tk.END)
        self.add_info("📝 Activity log cleared", "info")

    def save_log(self):
        """Save activity log to file"""
        try:
            log_content = self.info_text.get(1.0, tk.END)

            file_path = filedialog.asksaveasfilename(
                title="Save Activity Log",
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )

            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Advanced Folder Locker - Activity Log\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(log_content)

                self.add_info(f"💾 Log saved to: {Path(file_path).name}", "success")
                messagebox.showinfo("Log Saved", f"Activity log saved successfully!\n\n{file_path}")

        except Exception as e:
            error_msg = str(e)
            self.add_info(f"❌ Failed to save log: {error_msg}", "error")
            messagebox.showerror("Error", f"Failed to save log:\n\n{error_msg}")

    def refresh_stats(self):
        """Refresh statistics display"""
        # This would typically update the stats panel
        # For now, we'll just add a log entry
        self.add_info("🔄 Statistics refreshed", "info")

    def refresh_locked_folders(self, tree):
        """Refresh locked folders list"""
        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)

        # Reload data
        passwords = self.config.load_passwords()
        for folder_name, data in passwords.items():
            if isinstance(data, dict):
                created = data.get('created', 'Unknown')
                if created != 'Unknown':
                    try:
                        created_dt = datetime.fromisoformat(created)
                        created = created_dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        pass

                access_count = data.get('access_count', 0)
                file_path = data.get('file_path', 'Unknown')
                if file_path and len(file_path) > 50:
                    file_path = "..." + file_path[-47:]
            else:
                created = 'Unknown'
                access_count = 0
                file_path = 'Unknown'

            tree.insert('', tk.END, values=(folder_name, created, access_count, file_path))

    def center_window(self):
        """Center the main window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def center_dialog(self, dialog):
        """Center dialog on parent window"""
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

    def load_window_state(self):
        """Load saved window state"""
        try:
            window_state = self.config.get_config_value('window_state', {})
            if window_state:
                geometry = window_state.get('geometry')
                if geometry:
                    self.root.geometry(geometry)
        except Exception as e:
            print(f"Failed to load window state: {e}")

    def save_window_state(self):
        """Save current window state"""
        try:
            window_state = {
                'geometry': self.root.geometry()
            }
            self.config.set_config_value('window_state', window_state)
        except Exception as e:
            print(f"Failed to save window state: {e}")

    def run_in_thread(self, target, *args):
        """Run function in separate thread"""
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()

    def on_closing(self):
        """Handle application closing"""
        if self.is_processing:
            if not messagebox.askyesno("Operation in Progress",
                                       f"An operation is currently in progress: {self.current_operation}\n\n"
                                       "Closing now may cause data corruption.\n\n"
                                       "Are you sure you want to exit?"):
                return

        # Save window state
        self.save_window_state()

        # Save config
        self.config.save_config()

        # Add closing message
        self.add_info("👋 Application closing...", "info")

        # Close application
        self.root.quit()
        self.root.destroy()

    def run(self):
        """Start the GUI application"""
        try:
            # Mark first run as complete
            if self.config.get_config_value('first_run', True):
                self.config.set_config_value('first_run', False)
                self.add_info("🎉 Welcome to Advanced Folder Locker! First run setup complete.", "success")

            # Start main loop
            self.root.mainloop()

        except KeyboardInterrupt:
            print("\nApplication interrupted by user")
        except Exception as e:
            print(f"GUI Error: {e}")
            messagebox.showerror("Application Error", f"An unexpected error occurred:\n\n{e}")
        finally:
            try:
                self.root.quit()
            except:
                pass







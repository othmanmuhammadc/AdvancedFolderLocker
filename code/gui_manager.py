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


class ModernGUI:
    """Modern GUI with dark theme matching Figma design"""

    def __init__(self, encryption_manager, config):
        self.encryption_manager = encryption_manager
        self.config = config
        self.root = tk.Tk()
        self.is_processing = False
        self.current_operation = None

        # Dark theme colors matching Figma design
        self.colors = {
            'bg_primary': '#2B3544',  # Main background
            'bg_secondary': '#374151',  # Secondary background
            'bg_panel': '#4B5563',  # Panel background
            'accent_blue': '#3B82F6',  # Blue accent buttons
            'text_primary': '#F9FAFB',  # Primary text
            'text_secondary': '#D1D5DB',  # Secondary text
            'text_muted': '#9CA3AF',  # Muted text
            'success': '#10B981',  # Success color
            'warning': '#F59E0B',  # Warning color
            'error': '#EF4444'  # Error color
        }

        self.setup_ui()
        self.setup_styles()

    def setup_styles(self):
        """Setup dark theme styles"""
        # Configure root window
        self.root.configure(bg=self.colors['bg_primary'])

        # Create custom style
        style = ttk.Style()

        # Configure dark theme
        style.theme_use('clam')

        # Configure button styles
        style.configure('Accent.TButton',
                        background=self.colors['accent_blue'],
                        foreground='white',
                        borderwidth=0,
                        focuscolor='none',
                        font=('Arial', 10, 'bold'),
                        padding=(20, 12))

        style.map('Accent.TButton',
                  background=[('active', '#2563EB'),
                              ('pressed', '#1D4ED8')])

        # Configure frame styles
        style.configure('Dark.TFrame',
                        background=self.colors['bg_primary'],
                        borderwidth=0)

        style.configure('Panel.TFrame',
                        background=self.colors['bg_secondary'],
                        borderwidth=1,
                        relief='solid')

        # Configure label styles
        style.configure('Title.TLabel',
                        background=self.colors['bg_primary'],
                        foreground=self.colors['text_primary'],
                        font=('Arial', 18, 'bold'))

        style.configure('Header.TLabel',
                        background=self.colors['bg_secondary'],
                        foreground=self.colors['text_primary'],
                        font=('Arial', 12, 'bold'))

        style.configure('Normal.TLabel',
                        background=self.colors['bg_primary'],
                        foreground=self.colors['text_secondary'],
                        font=('Arial', 9))

    def setup_ui(self):
        """Setup the user interface matching Figma design"""
        self.root.title("Advanced Folder Locker")
        self.root.geometry("900x650")
        self.root.configure(bg=self.colors['bg_primary'])
        self.root.minsize(800, 600)

        # Create main container
        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Create header
        self.create_header(main_container)

        # Create main content area
        content_frame = tk.Frame(main_container, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))

        # Create left and right panels
        self.create_left_panel(content_frame)
        self.create_right_panel(content_frame)

        # Center window on screen
        self.center_window()

    def create_header(self, parent):
        """Create application header"""
        header_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        header_frame.pack(fill=tk.X, pady=(0, 20))

        # Title
        title_label = tk.Label(header_frame,
                               text="Advanced Folder Locker",
                               bg=self.colors['bg_primary'],
                               fg=self.colors['text_primary'],
                               font=('Arial', 20, 'bold'))
        title_label.pack()

    def create_left_panel(self, parent):
        """Create left operations panel"""
        left_frame = tk.Frame(parent, bg=self.colors['bg_secondary'], width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left_frame.pack_propagate(False)

        # Add padding inside the panel
        button_container = tk.Frame(left_frame, bg=self.colors['bg_secondary'])
        button_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Create operation buttons with proper spacing
        buttons = [
            ("Lock folder", self.encrypt_folder_gui),
            ("Unlock folder", self.decrypt_folder_gui),
            ("view locked Folders", self.show_locked_folders),
            ("Password manager", self.show_password_manager),
            ("Activity History", self.show_activity_history),
            ("clear All Data", self.clear_all_data)
        ]

        self.operation_buttons = []
        for i, (text, command) in enumerate(buttons):
            btn = tk.Button(button_container,
                            text=text,
                            command=command,
                            bg=self.colors['accent_blue'],
                            fg='white',
                            font=('Arial', 10, 'bold'),
                            border=0,
                            relief='flat',
                            cursor='hand2',
                            pady=12,
                            width=20)

            # Add hover effects
            btn.bind('<Enter>', lambda e, b=btn: b.configure(bg='#2563EB'))
            btn.bind('<Leave>', lambda e, b=btn: b.configure(bg=self.colors['accent_blue']))

            btn.pack(fill=tk.X, pady=(0, 15))
            self.operation_buttons.append(btn)

    def create_right_panel(self, parent):
        """Create right activity log panel"""
        right_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Activity Log header
        header_frame = tk.Frame(right_frame, bg=self.colors['accent_blue'], height=40)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        header_label = tk.Label(header_frame,
                                text="Activity Log",
                                bg=self.colors['accent_blue'],
                                fg='white',
                                font=('Arial', 12, 'bold'))
        header_label.pack(expand=True)

        # Log content area
        log_container = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        log_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Create scrolled text widget with dark theme
        self.activity_log = ScrolledText(log_container,
                                         bg='#1F2937',
                                         fg=self.colors['text_secondary'],
                                         font=('Consolas', 9),
                                         insertbackground=self.colors['text_primary'],
                                         selectbackground=self.colors['accent_blue'],
                                         selectforeground='white',
                                         border=0,
                                         wrap=tk.WORD)
        self.activity_log.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for colored output
        self.activity_log.tag_configure("success", foreground=self.colors['success'])
        self.activity_log.tag_configure("warning", foreground=self.colors['warning'])
        self.activity_log.tag_configure("error", foreground=self.colors['error'])
        self.activity_log.tag_configure("info", foreground=self.colors['accent_blue'])

        # Bottom button frame
        bottom_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        bottom_frame.pack(fill=tk.X, padx=15, pady=(0, 15))

        # Clear and Save log buttons
        clear_btn = tk.Button(bottom_frame,
                              text="clear log",
                              command=self.clear_log,
                              bg=self.colors['accent_blue'],
                              fg='white',
                              font=('Arial', 9, 'bold'),
                              border=0,
                              relief='flat',
                              cursor='hand2',
                              padx=20,
                              pady=8)
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))

        save_btn = tk.Button(bottom_frame,
                             text="save log",
                             command=self.save_log,
                             bg=self.colors['accent_blue'],
                             fg='white',
                             font=('Arial', 9, 'bold'),
                             border=0,
                             relief='flat',
                             cursor='hand2',
                             padx=20,
                             pady=8)
        save_btn.pack(side=tk.LEFT)

        # Add hover effects for bottom buttons
        for btn in [clear_btn, save_btn]:
            btn.bind('<Enter>', lambda e, b=btn: b.configure(bg='#2563EB'))
            btn.bind('<Leave>', lambda e, b=btn: b.configure(bg=self.colors['accent_blue']))

        # Add welcome message
        self.add_log_entry("Welcome to Advanced Folder Locker v2.0! 🎉", "success")
        self.add_log_entry("Enhanced security with military-grade encryption", "info")
        self.add_log_entry("Ready to secure your folders! 🔒", "success")

    def add_log_entry(self, message: str, tag: str = "info"):
        """Add message to activity log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"

        self.activity_log.insert(tk.END, formatted_message, tag)
        self.activity_log.see(tk.END)
        self.root.update_idletasks()

    def set_processing_state(self, processing: bool):
        """Set processing state and update UI"""
        self.is_processing = processing

        # Update button states
        state = tk.DISABLED if processing else tk.NORMAL
        for btn in self.operation_buttons:
            btn.config(state=state)

    def encrypt_folder_gui(self):
        """Handle folder encryption"""
        if self.is_processing:
            messagebox.showwarning("Warning", "Another operation is in progress. Please wait...")
            return

        folder_path = filedialog.askdirectory(title="Select folder to lock")
        if not folder_path:
            return

        folder = Path(folder_path)

        # Validation
        if not folder.exists() or not folder.is_dir():
            messagebox.showerror("Error", "Invalid folder selected!")
            return

        # Check if folder has files
        files = list(folder.rglob('*'))
        if not any(f.is_file() for f in files):
            messagebox.showwarning("Warning", "The selected folder is empty!")
            return

        # Get password
        password = self.get_password("Create Password", f"Create password for '{folder.name}':")
        if not password:
            return

        # Confirm password
        confirm_password = self.get_password("Confirm Password", "Re-enter the password:")
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        # Run encryption in thread
        self.run_in_thread(self._encrypt_folder_thread, folder_path, password)

    def _encrypt_folder_thread(self, folder_path: str, password: str):
        """Encryption thread"""
        try:
            folder_name = Path(folder_path).name

            self.root.after(0, lambda: self.set_processing_state(True))
            self.root.after(0, lambda: self.add_log_entry(f"🔄 Starting encryption: {folder_name}", "info"))

            # Perform encryption
            encrypted_file = self.encryption_manager.encrypt_folder(folder_path, password)

            # Save password hash
            password_hash = self.encryption_manager.hash_password(password)
            self.config.save_password(folder_name, password_hash, encrypted_file)

            # Add to history
            self.config.add_to_history("encrypt", folder_name, "success")

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"✅ Folder encrypted successfully: {folder_name}", "success"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Folder '{folder_name}' locked successfully!"))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"❌ Encryption failed: {error_msg}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to lock folder:\n\n{error_msg}"))

    def decrypt_folder_gui(self):
        """Handle folder decryption"""
        if self.is_processing:
            messagebox.showwarning("Warning", "Another operation is in progress. Please wait...")
            return

        encrypted_file = filedialog.askopenfilename(
            title="Select encrypted folder file",
            filetypes=[("Locked Files", "*.locked"), ("All Files", "*.*")]
        )

        if not encrypted_file:
            return

        # Get password
        folder_name = Path(encrypted_file).stem
        password = self.get_password("Enter Password", f"Enter password for '{folder_name}':")
        if not password:
            return

        # Run decryption in thread
        self.run_in_thread(self._decrypt_folder_thread, encrypted_file, password)

    def _decrypt_folder_thread(self, encrypted_file: str, password: str):
        """Decryption thread"""
        try:
            folder_name = Path(encrypted_file).stem

            self.root.after(0, lambda: self.set_processing_state(True))
            self.root.after(0, lambda: self.add_log_entry(f"🔄 Starting decryption: {folder_name}", "info"))

            # Perform decryption
            decrypted_folder = self.encryption_manager.decrypt_folder(encrypted_file, password)

            # Remove password from storage
            self.config.remove_password(folder_name)

            # Add to history
            self.config.add_to_history("decrypt", folder_name, "success")

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"✅ Folder decrypted successfully: {folder_name}", "success"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Folder '{folder_name}' unlocked successfully!"))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"❌ Decryption failed: {error_msg}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to unlock folder:\n\n{error_msg}"))

    def get_password(self, title: str, message: str) -> str:
        """Get password from user with custom dialog"""
        # Create custom password dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.configure(bg=self.colors['bg_primary'])
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        result = [None]

        # Create dialog content
        main_frame = tk.Frame(dialog, bg=self.colors['bg_primary'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        # Message
        tk.Label(main_frame, text=message,
                 bg=self.colors['bg_primary'],
                 fg=self.colors['text_primary'],
                 font=('Arial', 10)).pack(pady=(0, 20))

        # Password entry
        password_var = tk.StringVar()
        password_entry = tk.Entry(main_frame, textvariable=password_var,
                                  show="*", font=('Arial', 10),
                                  bg=self.colors['bg_panel'],
                                  fg=self.colors['text_primary'],
                                  insertbackground=self.colors['text_primary'],
                                  relief='flat', bd=5)
        password_entry.pack(fill=tk.X, pady=(0, 20))
        password_entry.focus()

        # Buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        button_frame.pack(fill=tk.X)

        def ok_clicked():
            result[0] = password_var.get()
            dialog.destroy()

        def cancel_clicked():
            dialog.destroy()

        cancel_btn = tk.Button(button_frame, text="Cancel", command=cancel_clicked,
                               bg=self.colors['bg_panel'], fg=self.colors['text_primary'],
                               font=('Arial', 9), border=0, relief='flat',
                               cursor='hand2', padx=20, pady=8)
        cancel_btn.pack(side=tk.RIGHT)

        ok_btn = tk.Button(button_frame, text="OK", command=ok_clicked,
                           bg=self.colors['accent_blue'], fg='white',
                           font=('Arial', 9, 'bold'), border=0, relief='flat',
                           cursor='hand2', padx=20, pady=8)
        ok_btn.pack(side=tk.RIGHT, padx=(0, 10))

        # Bind Enter key
        dialog.bind('<Return>', lambda e: ok_clicked())

        dialog.wait_window()
        return result[0] or ""

    def show_locked_folders(self):
        """Show locked folders dialog"""
        passwords = self.config.load_passwords()

        if not passwords:
            messagebox.showinfo("No Locked Folders", "No locked folders found.")
            return

        self.add_log_entry(f"📋 Viewing {len(passwords)} locked folders", "info")

        # Create simple info dialog
        folder_list = "\n".join([f"• {folder}" for folder in passwords.keys()])
        messagebox.showinfo("Locked Folders", f"Locked Folders ({len(passwords)}):\n\n{folder_list}")

    def show_password_manager(self):
        """Show password manager"""
        passwords = self.config.load_passwords()
        self.add_log_entry("🔑 Opening password manager", "info")

        if not passwords:
            messagebox.showinfo("Password Manager", "No saved passwords found.")
            return

        # Simple password manager dialog
        folder_list = "\n".join([f"• {folder}" for folder in passwords.keys()])
        messagebox.showinfo("Password Manager", f"Saved Passwords ({len(passwords)}):\n\n{folder_list}")

    def show_activity_history(self):
        """Show activity history"""
        history = self.config.load_history()
        self.add_log_entry("📊 Viewing activity history", "info")

        if not history:
            messagebox.showinfo("Activity History", "No activity history found.")
            return

        # Show recent activities
        recent_activities = history[-10:]  # Last 10 activities
        activity_text = "\n".join([
            f"• {entry.get('action', '').title()}: {entry.get('folder_name', 'Unknown')} - {entry.get('status', '').title()}"
            for entry in reversed(recent_activities)
        ])
        messagebox.showinfo("Activity History", f"Recent Activities:\n\n{activity_text}")

    def clear_all_data(self):
        """Clear all application data"""
        if messagebox.askyesno("Clear All Data",
                               "This will remove all saved passwords and history.\n\n"
                               "Encrypted files will NOT be affected.\n\n"
                               "Continue?"):
            try:
                self.config.clear_all_data()
                self.add_log_entry("🧹 All application data cleared", "warning")
                messagebox.showinfo("Data Cleared", "All application data cleared successfully!")
            except Exception as e:
                self.add_log_entry(f"❌ Failed to clear data: {str(e)}", "error")
                messagebox.showerror("Error", f"Failed to clear data: {str(e)}")

    def clear_log(self):
        """Clear activity log"""
        self.activity_log.delete(1.0, tk.END)
        self.add_log_entry("📝 Activity log cleared", "info")

    def save_log(self):
        """Save activity log to file"""
        try:
            log_content = self.activity_log.get(1.0, tk.END)

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

                self.add_log_entry(f"💾 Log saved to: {Path(file_path).name}", "success")
                messagebox.showinfo("Log Saved", "Activity log saved successfully!")

        except Exception as e:
            self.add_log_entry(f"❌ Failed to save log: {str(e)}", "error")
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def center_dialog(self, dialog):
        """Center dialog on parent"""
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

    def run_in_thread(self, target, *args):
        """Run function in separate thread"""
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()

    def run(self):
        """Start the application"""
        try:
            self.root.mainloop()
        except Exception as e:
            print(f"GUI Error: {e}")




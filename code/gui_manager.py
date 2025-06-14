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


class AnimatedButton(tk.Button):
    """Custom animated button with hover effects and smooth transitions"""

    def __init__(self, parent, **kwargs):
        self.original_bg = kwargs.get('bg', '#3B82F6')
        self.hover_bg = kwargs.get('hover_bg', '#2563EB')
        self.pressed_bg = kwargs.get('pressed_bg', '#1D4ED8')

        # Remove custom kwargs before passing to Button
        if 'hover_bg' in kwargs:
            del kwargs['hover_bg']
        if 'pressed_bg' in kwargs:
            del kwargs['pressed_bg']

        super().__init__(parent, **kwargs)

        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.bind('<Button-1>', self.on_press)
        self.bind('<ButtonRelease-1>', self.on_release)

        # Animation variables
        self.animation_running = False
        self.current_color = self.original_bg

    def animate_color_transition(self, target_color, duration=200):
        """Smooth color transition animation"""
        if self.animation_running:
            return

        self.animation_running = True

        # Parse colors
        start_r, start_g, start_b = self.hex_to_rgb(self.current_color)
        end_r, end_g, end_b = self.hex_to_rgb(target_color)

        steps = 10
        step_duration = duration // steps

        for i in range(steps + 1):
            progress = i / steps

            # Interpolate colors
            r = int(start_r + (end_r - start_r) * progress)
            g = int(start_g + (end_g - start_g) * progress)
            b = int(start_b + (end_b - start_b) * progress)

            color = f"#{r:02x}{g:02x}{b:02x}"

            self.after(i * step_duration, lambda c=color: self.config(bg=c))

        self.current_color = target_color
        self.after(duration, lambda: setattr(self, 'animation_running', False))

    def hex_to_rgb(self, hex_color):
        """Convert hex color to RGB tuple"""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))

    def on_enter(self, event):
        """Handle mouse enter"""
        if not self.animation_running:
            self.animate_color_transition(self.hover_bg, 150)

    def on_leave(self, event):
        """Handle mouse leave"""
        if not self.animation_running:
            self.animate_color_transition(self.original_bg, 150)

    def on_press(self, event):
        """Handle button press"""
        self.config(bg=self.pressed_bg)

    def on_release(self, event):
        """Handle button release"""
        self.config(bg=self.hover_bg)


class BlurredFrame(tk.Frame):
    """Frame with blur effect simulation"""

    def __init__(self, parent, blur_strength=5, **kwargs):
        super().__init__(parent, **kwargs)
        self.blur_strength = blur_strength
        self.setup_blur_effect()

    def setup_blur_effect(self):
        """Setup blur effect using overlapping frames"""
        # Create multiple semi-transparent layers for blur effect
        for i in range(self.blur_strength):
            overlay = tk.Frame(self, bg=self['bg'], height=2, width=2)
            overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            overlay.configure(bg=self.lighten_color(self['bg'], 0.1 * i))

    def lighten_color(self, color, factor):
        """Lighten a color by a factor"""
        try:
            # Simple color lightening
            if color.startswith('#'):
                r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
                r = min(255, int(r + (255 - r) * factor))
                g = min(255, int(g + (255 - g) * factor))
                b = min(255, int(b + (255 - b) * factor))
                return f"#{r:02x}{g:02x}{b:02x}"
        except:
            pass
        return color


class ModernGUI:
    """Modern GUI with enhanced animations, blur effects, and file support"""

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
            'accent_hover': '#2563EB',  # Hover state
            'accent_pressed': '#1D4ED8',  # Pressed state
            'text_primary': '#F9FAFB',  # Primary text
            'text_secondary': '#D1D5DB',  # Secondary text
            'text_muted': '#9CA3AF',  # Muted text
            'success': '#10B981',  # Success color
            'warning': '#F59E0B',  # Warning color
            'error': '#EF4444'  # Error color
        }

        self.setup_ui()
        self.setup_animations()

    def setup_ui(self):
        """Setup the user interface matching Figma design"""
        self.root.title("Advanced Folder Locker")
        self.root.geometry("900x650")
        self.root.configure(bg=self.colors['bg_primary'])
        self.root.minsize(800, 600)

        # Create main container with blur effect
        main_container = BlurredFrame(self.root, bg=self.colors['bg_primary'], blur_strength=3)
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
        """Create application header with animations"""
        header_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        header_frame.pack(fill=tk.X, pady=(0, 20))

        # Animated title
        title_label = tk.Label(header_frame,
                               text="Advanced Folder Locker",
                               bg=self.colors['bg_primary'],
                               fg=self.colors['text_primary'],
                               font=('Arial', 20, 'bold'))
        title_label.pack()

        # Subtitle with fade-in effect
        subtitle_label = tk.Label(header_frame,
                                  text="Military-grade encryption for files and folders",
                                  bg=self.colors['bg_primary'],
                                  fg=self.colors['text_secondary'],
                                  font=('Arial', 10))
        subtitle_label.pack(pady=(5, 0))

        # Stats panel with animation
        self.create_animated_stats(header_frame)

    def create_animated_stats(self, parent):
        """Create animated statistics panel"""
        stats_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        stats_frame.pack(fill=tk.X, pady=(15, 0))

        stats = self.config.get_stats()

        # Create animated stat cards
        stats_container = tk.Frame(stats_frame, bg=self.colors['bg_primary'])
        stats_container.pack()

        self.stat_labels = []

        # Folders stat
        folder_frame = BlurredFrame(stats_container, bg=self.colors['bg_secondary'], blur_strength=2)
        folder_frame.pack(side=tk.LEFT, padx=(0, 15), pady=5)

        folder_label = tk.Label(folder_frame,
                                text=f"📁 Folders: {stats['locked_folders']}",
                                bg=self.colors['bg_secondary'],
                                fg=self.colors['text_primary'],
                                font=('Arial', 9, 'bold'),
                                padx=15, pady=8)
        folder_label.pack()
        self.stat_labels.append(folder_label)

        # Files stat
        file_frame = BlurredFrame(stats_container, bg=self.colors['bg_secondary'], blur_strength=2)
        file_frame.pack(side=tk.LEFT, padx=(0, 15), pady=5)

        file_label = tk.Label(file_frame,
                              text=f"📄 Files: {stats['locked_files']}",
                              bg=self.colors['bg_secondary'],
                              fg=self.colors['text_primary'],
                              font=('Arial', 9, 'bold'),
                              padx=15, pady=8)
        file_label.pack()
        self.stat_labels.append(file_label)

        # Operations stat
        ops_frame = BlurredFrame(stats_container, bg=self.colors['bg_secondary'], blur_strength=2)
        ops_frame.pack(side=tk.LEFT, pady=5)

        ops_label = tk.Label(ops_frame,
                             text=f"🔄 Operations: {stats['total_operations']}",
                             bg=self.colors['bg_secondary'],
                             fg=self.colors['text_primary'],
                             font=('Arial', 9, 'bold'),
                             padx=15, pady=8)
        ops_label.pack()
        self.stat_labels.append(ops_label)

    def create_left_panel(self, parent):
        """Create left operations panel with enhanced animations"""
        left_frame = BlurredFrame(parent, bg=self.colors['bg_secondary'], width=280, blur_strength=4)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left_frame.pack_propagate(False)

        # Add padding inside the panel
        button_container = tk.Frame(left_frame, bg=self.colors['bg_secondary'])
        button_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Create operation buttons with enhanced animations
        buttons_config = [
            ("🔐 Lock Folder", self.encrypt_folder_gui, "Lock and encrypt entire folders"),
            ("🔓 Unlock Folder", self.decrypt_folder_gui, "Unlock and decrypt folders"),
            ("📄 Lock File", self.encrypt_file_gui, "Lock individual files (txt, pdf, docx, etc.)"),
            ("📂 Unlock File", self.decrypt_file_gui, "Unlock individual files"),
            ("📋 View Locked Items", self.show_locked_items, "View all locked folders and files"),
            ("🔑 Password Manager", self.show_password_manager, "Manage saved passwords"),
            ("📊 Activity History", self.show_activity_history, "View operation history"),
            ("🧹 Clear All Data", self.clear_all_data, "Clear all saved data")
        ]

        self.operation_buttons = []
        for i, (text, command, tooltip) in enumerate(buttons_config):
            btn = AnimatedButton(button_container,
                                 text=text,
                                 command=command,
                                 bg=self.colors['accent_blue'],
                                 hover_bg=self.colors['accent_hover'],
                                 pressed_bg=self.colors['accent_pressed'],
                                 fg='white',
                                 font=('Arial', 10, 'bold'),
                                 border=0,
                                 relief='flat',
                                 cursor='hand2',
                                 pady=12,
                                 width=25)

            btn.pack(fill=tk.X, pady=(0, 12))
            self.operation_buttons.append(btn)

            # Add tooltip
            self.create_tooltip(btn, tooltip)

        # Add separator
        separator = tk.Frame(button_container, bg=self.colors['text_muted'], height=1)
        separator.pack(fill=tk.X, pady=(10, 20))

        # Security info panel
        self.create_security_info(button_container)

    def create_security_info(self, parent):
        """Create animated security information panel"""
        security_frame = BlurredFrame(parent, bg=self.colors['bg_panel'], blur_strength=2)
        security_frame.pack(fill=tk.X, pady=(10, 0))

        header_label = tk.Label(security_frame,
                                text="🔐 Security Features",
                                bg=self.colors['bg_panel'],
                                fg=self.colors['text_primary'],
                                font=('Arial', 10, 'bold'))
        header_label.pack(pady=(15, 10))

        security_features = [
            "• AES-256 Encryption",
            "• PBKDF2 Key Derivation",
            "• 100,000 Iterations",
            "• Secure Salt Generation",
            "• File & Folder Support"
        ]

        for feature in security_features:
            feature_label = tk.Label(security_frame,
                                     text=feature,
                                     bg=self.colors['bg_panel'],
                                     fg=self.colors['text_secondary'],
                                     font=('Arial', 8),
                                     anchor='w')
            feature_label.pack(fill=tk.X, padx=15, pady=1)

        # Add padding at bottom
        tk.Frame(security_frame, bg=self.colors['bg_panel'], height=15).pack()

    def create_right_panel(self, parent):
        """Create right activity log panel with enhanced design"""
        right_frame = BlurredFrame(parent, bg=self.colors['bg_secondary'], blur_strength=4)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Activity Log header with gradient effect
        header_frame = tk.Frame(right_frame, bg=self.colors['accent_blue'], height=45)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        header_label = tk.Label(header_frame,
                                text="📝 Activity Log",
                                bg=self.colors['accent_blue'],
                                fg='white',
                                font=('Arial', 12, 'bold'))
        header_label.pack(expand=True)

        # Log content area with blur background
        log_container = BlurredFrame(right_frame, bg=self.colors['bg_secondary'], blur_strength=2)
        log_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Create scrolled text widget with enhanced styling
        self.activity_log = ScrolledText(log_container,
                                         bg='#1F2937',
                                         fg=self.colors['text_secondary'],
                                         font=('Consolas', 9),
                                         insertbackground=self.colors['text_primary'],
                                         selectbackground=self.colors['accent_blue'],
                                         selectforeground='white',
                                         border=0,
                                         wrap=tk.WORD,
                                         relief='flat')
        self.activity_log.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for colored output
        self.activity_log.tag_configure("success", foreground=self.colors['success'])
        self.activity_log.tag_configure("warning", foreground=self.colors['warning'])
        self.activity_log.tag_configure("error", foreground=self.colors['error'])
        self.activity_log.tag_configure("info", foreground=self.colors['accent_blue'])

        # Bottom button frame with animations
        bottom_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        bottom_frame.pack(fill=tk.X, padx=15, pady=(0, 15))

        # Clear and Save log buttons with animations
        clear_btn = AnimatedButton(bottom_frame,
                                   text="🗑️ Clear Log",
                                   command=self.clear_log,
                                   bg=self.colors['accent_blue'],
                                   hover_bg=self.colors['accent_hover'],
                                   pressed_bg=self.colors['accent_pressed'],
                                   fg='white',
                                   font=('Arial', 9, 'bold'),
                                   border=0,
                                   relief='flat',
                                   cursor='hand2',
                                   padx=20,
                                   pady=8)
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))

        save_btn = AnimatedButton(bottom_frame,
                                  text="💾 Save Log",
                                  command=self.save_log,
                                  bg=self.colors['accent_blue'],
                                  hover_bg=self.colors['accent_hover'],
                                  pressed_bg=self.colors['accent_pressed'],
                                  fg='white',
                                  font=('Arial', 9, 'bold'),
                                  border=0,
                                  relief='flat',
                                  cursor='hand2',
                                  padx=20,
                                  pady=8)
        save_btn.pack(side=tk.LEFT)

        # Add welcome messages with animations
        self.add_welcome_messages()

    def create_tooltip(self, widget, text):
        """Create tooltip for widget"""

        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")

            label = tk.Label(tooltip, text=text,
                             bg=self.colors['bg_panel'],
                             fg=self.colors['text_primary'],
                             font=('Arial', 8),
                             relief='solid',
                             borderwidth=1,
                             padx=8, pady=4)
            label.pack()

            def hide_tooltip():
                tooltip.destroy()

            tooltip.after(3000, hide_tooltip)  # Auto-hide after 3 seconds

        widget.bind('<Enter>', show_tooltip)

    def setup_animations(self):
        """Setup various animations and effects"""
        # Fade-in animation for main window
        self.root.attributes('-alpha', 0.0)
        self.fade_in_window()

        # Setup periodic animations
        self.animate_stats()

    def fade_in_window(self):
        """Fade in the main window"""
        alpha = self.root.attributes('-alpha')
        if alpha < 1.0:
            alpha += 0.05
            self.root.attributes('-alpha', alpha)
            self.root.after(30, self.fade_in_window)

    def animate_stats(self):
        """Animate statistics with periodic updates"""

        def update_stats():
            stats = self.config.get_stats()

            if hasattr(self, 'stat_labels') and len(self.stat_labels) >= 3:
                # Animate stat updates
                self.stat_labels[0].config(text=f"📁 Folders: {stats['locked_folders']}")
                self.stat_labels[1].config(text=f"📄 Files: {stats['locked_files']}")
                self.stat_labels[2].config(text=f"🔄 Operations: {stats['total_operations']}")

            # Schedule next update
            self.root.after(5000, update_stats)  # Update every 5 seconds

        # Start the animation loop
        self.root.after(1000, update_stats)

    def add_welcome_messages(self):
        """Add animated welcome messages to log"""
        welcome_messages = [
            ("🎉 Welcome to Advanced Folder Locker v2.0!", "success"),
            ("🔒 Enhanced security with military-grade encryption", "info"),
            ("📁 Lock folders and individual files with ease", "info"),
            ("🔐 All passwords are securely hashed and stored", "info"),
            ("✨ New: File encryption support for all file types!", "success"),
            ("🚀 Ready to secure your data!", "success")
        ]

        def add_message_with_delay(index):
            if index < len(welcome_messages):
                message, tag = welcome_messages[index]
                self.add_log_entry(message, tag)
                # Schedule next message
                self.root.after(800, lambda: add_message_with_delay(index + 1))

        # Start adding messages with delay
        self.root.after(500, lambda: add_message_with_delay(0))

    def add_log_entry(self, message: str, tag: str = "info"):
        """Add message to activity log with timestamp and animation"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"

        self.activity_log.insert(tk.END, formatted_message, tag)
        self.activity_log.see(tk.END)
        self.root.update_idletasks()

        # Add subtle animation to new log entry
        self.animate_log_entry()

    def animate_log_entry(self):
        """Animate new log entry"""
        # Simple flash animation for new entries
        original_bg = self.activity_log.cget('bg')
        flash_bg = self.colors['bg_panel']

        def flash():
            self.activity_log.config(bg=flash_bg)
            self.root.after(100, lambda: self.activity_log.config(bg=original_bg))

        flash()

    def set_processing_state(self, processing: bool, operation: str = ""):
        """Set processing state with enhanced animations"""
        self.is_processing = processing
        self.current_operation = operation if processing else None

        # Animate button states
        for btn in self.operation_buttons:
            if processing:
                btn.config(state=tk.DISABLED, bg=self.colors['text_muted'])
            else:
                btn.config(state=tk.NORMAL, bg=self.colors['accent_blue'])

        # Show processing animation
        if processing:
            self.show_processing_animation(operation)
        else:
            self.hide_processing_animation()

    def show_processing_animation(self, operation):
        """Show animated processing indicator"""
        if not hasattr(self, 'processing_label'):
            self.processing_label = tk.Label(self.root,
                                             text="",
                                             bg=self.colors['bg_primary'],
                                             fg=self.colors['accent_blue'],
                                             font=('Arial', 10, 'bold'))
            self.processing_label.place(relx=0.5, rely=0.95, anchor='center')

        # Animate processing text
        self.animate_processing_text(operation)

    def animate_processing_text(self, operation):
        """Animate processing text with dots"""
        if not self.is_processing:
            return

        dots = ["", ".", "..", "..."]
        dot_index = getattr(self, 'dot_index', 0)

        text = f"🔄 {operation}{dots[dot_index]}"
        self.processing_label.config(text=text)

        self.dot_index = (dot_index + 1) % len(dots)
        self.root.after(500, lambda: self.animate_processing_text(operation))

    def hide_processing_animation(self):
        """Hide processing animation"""
        if hasattr(self, 'processing_label'):
            self.processing_label.place_forget()

    def encrypt_file_gui(self):
        """Handle individual file encryption with animations"""
        if self.is_processing:
            messagebox.showwarning("Warning", "Another operation is in progress. Please wait...")
            return

        # File dialog for various file types
        file_path = filedialog.askopenfilename(
            title="Select file to lock",
            filetypes=[
                ("Text Files", "*.txt"),
                ("PDF Files", "*.pdf"),
                ("Word Documents", "*.docx *.doc"),
                ("Excel Files", "*.xlsx *.xls"),
                ("PowerPoint Files", "*.pptx *.ppt"),
                ("Image Files", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("Video Files", "*.mp4 *.avi *.mkv *.mov"),
                ("Audio Files", "*.mp3 *.wav *.flac"),
                ("All Files", "*.*")
            ]
        )

        if not file_path:
            return

        file = Path(file_path)

        # Validation with animations
        if not file.exists() or not file.is_file():
            messagebox.showerror("Error", "Invalid file selected!")
            return

        # Show file info with animation
        file_size = file.stat().st_size
        size_mb = file_size / (1024 * 1024)

        file_info = f"File: {file.name}\nSize: {size_mb:.2f} MB\nType: {file.suffix.upper()}"

        if not messagebox.askyesno("Confirm Lock", f"Lock this file?\n\n{file_info}"):
            return

        # Get password with enhanced dialog
        password = self.get_password("Create Password", f"Create password for '{file.name}':")
        if not password:
            return

        # Confirm password
        confirm_password = self.get_password("Confirm Password", "Re-enter the password:")
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        # Run encryption in thread with animation
        self.run_in_thread(self._encrypt_file_thread, file_path, password)

    def _encrypt_file_thread(self, file_path: str, password: str):
        """File encryption thread with enhanced feedback"""
        try:
            file_name = Path(file_path).name

            self.root.after(0, lambda: self.set_processing_state(True, f"Encrypting {file_name}"))
            self.root.after(0, lambda: self.add_log_entry(f"🔄 Starting file encryption: {file_name}", "info"))

            # Perform encryption
            encrypted_file = self.encryption_manager.encrypt_file(file_path, password)

            # Save password hash
            password_hash = self.encryption_manager.hash_password(password)
            self.config.save_password(file_name, password_hash, encrypted_file, "file")

            # Add to history
            self.config.add_to_history("encrypt", file_name, "success", "file")

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"✅ File encrypted successfully: {file_name}", "success"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"File '{file_name}' locked successfully!"))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"❌ File encryption failed: {error_msg}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to lock file:\n\n{error_msg}"))

    def decrypt_file_gui(self):
        """Handle individual file decryption with animations"""
        if self.is_processing:
            messagebox.showwarning("Warning", "Another operation is in progress. Please wait...")
            return

        encrypted_file = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("Locked Files", "*.locked"), ("All Files", "*.*")]
        )

        if not encrypted_file:
            return

        # Get file info
        file_info = self.encryption_manager.get_file_info(encrypted_file)
        if "error" in file_info:
            messagebox.showerror("Error", f"Invalid encrypted file: {file_info['error']}")
            return

        if file_info.get('item_type') != 'file':
            messagebox.showerror("Error", "This is not an encrypted file. Use 'Unlock Folder' instead.")
            return

        # Get password
        file_name = Path(encrypted_file).stem
        password = self.get_password("Enter Password", f"Enter password for '{file_name}':")
        if not password:
            return

        # Run decryption in thread
        self.run_in_thread(self._decrypt_file_thread, encrypted_file, password)

    def _decrypt_file_thread(self, encrypted_file: str, password: str):
        """File decryption thread with enhanced feedback"""
        try:
            file_name = Path(encrypted_file).stem

            self.root.after(0, lambda: self.set_processing_state(True, f"Decrypting {file_name}"))
            self.root.after(0, lambda: self.add_log_entry(f"🔄 Starting file decryption: {file_name}", "info"))

            # Perform decryption
            decrypted_file = self.encryption_manager.decrypt_file(encrypted_file, password)

            # Remove password from storage
            self.config.remove_password(file_name)

            # Add to history
            self.config.add_to_history("decrypt", file_name, "success", "file")

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"✅ File decrypted successfully: {file_name}", "success"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"File '{file_name}' unlocked successfully!"))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"❌ File decryption failed: {error_msg}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to unlock file:\n\n{error_msg}"))

    def encrypt_folder_gui(self):
        """Handle folder encryption with enhanced animations"""
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
        """Folder encryption thread"""
        try:
            folder_name = Path(folder_path).name

            self.root.after(0, lambda: self.set_processing_state(True, f"Encrypting {folder_name}"))
            self.root.after(0, lambda: self.add_log_entry(f"🔄 Starting folder encryption: {folder_name}", "info"))

            # Perform encryption
            encrypted_file = self.encryption_manager.encrypt_folder(folder_path, password)

            # Save password hash
            password_hash = self.encryption_manager.hash_password(password)
            self.config.save_password(folder_name, password_hash, encrypted_file, "folder")

            # Add to history
            self.config.add_to_history("encrypt", folder_name, "success", "folder")

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"✅ Folder encrypted successfully: {folder_name}", "success"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Folder '{folder_name}' locked successfully!"))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"❌ Folder encryption failed: {error_msg}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to lock folder:\n\n{error_msg}"))

    def decrypt_folder_gui(self):
        """Handle folder decryption with animations"""
        if self.is_processing:
            messagebox.showwarning("Warning", "Another operation is in progress. Please wait...")
            return

        encrypted_file = filedialog.askopenfilename(
            title="Select encrypted folder file",
            filetypes=[("Locked Files", "*.locked"), ("All Files", "*.*")]
        )

        if not encrypted_file:
            return

        # Get file info
        file_info = self.encryption_manager.get_file_info(encrypted_file)
        if "error" in file_info:
            messagebox.showerror("Error", f"Invalid encrypted file: {file_info['error']}")
            return

        if file_info.get('item_type') == 'file':
            messagebox.showerror("Error", "This is an encrypted file. Use 'Unlock File' instead.")
            return

        # Get password
        folder_name = Path(encrypted_file).stem
        password = self.get_password("Enter Password", f"Enter password for '{folder_name}':")
        if not password:
            return

        # Run decryption in thread
        self.run_in_thread(self._decrypt_folder_thread, encrypted_file, password)

    def _decrypt_folder_thread(self, encrypted_file: str, password: str):
        """Folder decryption thread"""
        try:
            folder_name = Path(encrypted_file).stem

            self.root.after(0, lambda: self.set_processing_state(True, f"Decrypting {folder_name}"))
            self.root.after(0, lambda: self.add_log_entry(f"🔄 Starting folder decryption: {folder_name}", "info"))

            # Perform decryption
            decrypted_folder = self.encryption_manager.decrypt_folder(encrypted_file, password)

            # Remove password from storage
            self.config.remove_password(folder_name)

            # Add to history
            self.config.add_to_history("decrypt", folder_name, "success", "folder")

            # Update UI
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"✅ Folder decrypted successfully: {folder_name}", "success"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Folder '{folder_name}' unlocked successfully!"))

        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.set_processing_state(False))
            self.root.after(0, lambda: self.add_log_entry(f"❌ Folder decryption failed: {error_msg}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to unlock folder:\n\n{error_msg}"))

    def get_password(self, title: str, message: str) -> str:
        """Get password from user with enhanced dialog"""
        # Create custom password dialog with blur effect
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.configure(bg=self.colors['bg_primary'])
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.transient(self.root)

        # Add blur effect
        dialog.attributes('-alpha', 0.0)

        # Center dialog
        self.center_dialog(dialog)

        result = [None]

        # Create dialog content with blur background
        main_frame = BlurredFrame(dialog, bg=self.colors['bg_primary'], blur_strength=3)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        # Message
        tk.Label(main_frame, text=message,
                 bg=self.colors['bg_primary'],
                 fg=self.colors['text_primary'],
                 font=('Arial', 10)).pack(pady=(0, 20))

        # Password entry with enhanced styling
        password_var = tk.StringVar()
        password_entry = tk.Entry(main_frame, textvariable=password_var,
                                  show="*", font=('Arial', 10),
                                  bg=self.colors['bg_panel'],
                                  fg=self.colors['text_primary'],
                                  insertbackground=self.colors['text_primary'],
                                  relief='flat', bd=5)
        password_entry.pack(fill=tk.X, pady=(0, 20))
        password_entry.focus()

        # Buttons with animations
        button_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        button_frame.pack(fill=tk.X)

        def ok_clicked():
            result[0] = password_var.get()
            dialog.destroy()

        def cancel_clicked():
            dialog.destroy()

        cancel_btn = AnimatedButton(button_frame, text="Cancel", command=cancel_clicked,
                                    bg=self.colors['bg_panel'],
                                    hover_bg=self.colors['text_muted'],
                                    fg=self.colors['text_primary'],
                                    font=('Arial', 9), border=0, relief='flat',
                                    cursor='hand2', padx=20, pady=8)
        cancel_btn.pack(side=tk.RIGHT)

        ok_btn = AnimatedButton(button_frame, text="OK", command=ok_clicked,
                                bg=self.colors['accent_blue'],
                                hover_bg=self.colors['accent_hover'],
                                fg='white',
                                font=('Arial', 9, 'bold'), border=0, relief='flat',
                                cursor='hand2', padx=20, pady=8)
        ok_btn.pack(side=tk.RIGHT, padx=(0, 10))

        # Bind Enter key
        dialog.bind('<Return>', lambda e: ok_clicked())

        # Fade in dialog
        def fade_in_dialog():
            alpha = dialog.attributes('-alpha')
            if alpha < 0.95:
                alpha += 0.05
                dialog.attributes('-alpha', alpha)
                dialog.after(30, fade_in_dialog)

        fade_in_dialog()

        dialog.wait_window()
        return result[0] or ""

    def show_locked_items(self):
        """Show locked folders and files with enhanced interface"""
        passwords = self.config.load_passwords()

        if not passwords:
            messagebox.showinfo("No Locked Items", "No locked folders or files found.")
            return

        self.add_log_entry(f"📋 Viewing {len(passwords)} locked items", "info")

        # Create enhanced dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Locked Items")
        dialog.geometry("700x500")
        dialog.configure(bg=self.colors['bg_primary'])
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame with blur effect
        main_frame = BlurredFrame(dialog, bg=self.colors['bg_primary'], blur_strength=3)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        title_label = tk.Label(main_frame,
                               text="🔒 Locked Items",
                               bg=self.colors['bg_primary'],
                               fg=self.colors['text_primary'],
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 15))

        # Stats
        folders = sum(1 for p in passwords.values() if isinstance(p, dict) and p.get("item_type", "folder") == "folder")
        files = sum(1 for p in passwords.values() if isinstance(p, dict) and p.get("item_type", "folder") == "file")

        stats_label = tk.Label(main_frame,
                               text=f"📁 {folders} Folders  •  📄 {files} Files",
                               bg=self.colors['bg_primary'],
                               fg=self.colors['text_secondary'],
                               font=('Arial', 10))
        stats_label.pack(pady=(0, 15))

        # Create treeview with enhanced styling
        tree_frame = tk.Frame(main_frame, bg=self.colors['bg_secondary'])
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('Type', 'Name', 'Created', 'Access Count')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)

        # Configure columns
        tree.heading('Type', text='Type')
        tree.heading('Name', text='Name')
        tree.heading('Created', text='Created')
        tree.heading('Access Count', text='Access Count')

        tree.column('Type', width=80)
        tree.column('Name', width=200)
        tree.column('Created', width=150)
        tree.column('Access Count', width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        # Pack treeview and scrollbar
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate data
        for item_name, data in passwords.items():
            if isinstance(data, dict):
                item_type = data.get('item_type', 'folder')
                type_icon = "📁" if item_type == "folder" else "📄"

                created = data.get('created', 'Unknown')
                if created != 'Unknown':
                    try:
                        created_dt = datetime.fromisoformat(created)
                        created = created_dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        pass

                access_count = data.get('access_count', 0)
            else:
                type_icon = "📁"
                created = 'Unknown'
                access_count = 0

            tree.insert('', tk.END, values=(type_icon, item_name, created, access_count))

        # Button frame
        button_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        button_frame.pack(fill=tk.X, pady=(15, 0))

        close_btn = AnimatedButton(button_frame, text="Close", command=dialog.destroy,
                                   bg=self.colors['accent_blue'],
                                   hover_bg=self.colors['accent_hover'],
                                   fg='white', font=('Arial', 9, 'bold'),
                                   padx=20, pady=8)
        close_btn.pack(side=tk.RIGHT)

    def show_password_manager(self):
        """Show password manager with enhanced interface"""
        passwords = self.config.load_passwords()
        self.add_log_entry("🔑 Opening password manager", "info")

        if not passwords:
            messagebox.showinfo("Password Manager", "No saved passwords found.")
            return

        # Enhanced password manager dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Manager")
        dialog.geometry("600x400")
        dialog.configure(bg=self.colors['bg_primary'])
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame with blur effect
        main_frame = BlurredFrame(dialog, bg=self.colors['bg_primary'], blur_strength=3)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        title_label = tk.Label(main_frame,
                               text="🔑 Password Manager",
                               bg=self.colors['bg_primary'],
                               fg=self.colors['text_primary'],
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 15))

        # List of items
        listbox_frame = BlurredFrame(main_frame, bg=self.colors['bg_secondary'], blur_strength=2)
        listbox_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        listbox = tk.Listbox(listbox_frame, font=('Arial', 10),
                             bg=self.colors['bg_secondary'],
                             fg=self.colors['text_primary'],
                             selectbackground=self.colors['accent_blue'],
                             selectforeground='white',
                             relief='flat')
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)

        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=15)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=15)

        # Populate listbox
        for item_name, data in passwords.items():
            if isinstance(data, dict):
                item_type = data.get('item_type', 'folder')
                icon = "📁" if item_type == "folder" else "📄"
                listbox.insert(tk.END, f"{icon} {item_name}")
            else:
                listbox.insert(tk.END, f"📁 {item_name}")

        # Button frame
        button_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        button_frame.pack(fill=tk.X)

        def remove_selected():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select an item to remove.")
                return

            item_text = listbox.get(selection[0])
            item_name = item_text.split(' ', 1)[1]  # Remove icon

            if messagebox.askyesno("Confirm Removal",
                                   f"Remove password for '{item_name}'?\n\nThis will not affect the encrypted file."):
                self.config.remove_password(item_name)
                listbox.delete(selection[0])
                self.add_log_entry(f"🗑️ Password removed for: {item_name}", "warning")

        remove_btn = AnimatedButton(button_frame, text="🗑️ Remove Selected", command=remove_selected,
                                    bg=self.colors['warning'],
                                    hover_bg='#D97706',
                                    fg='white', font=('Arial', 9, 'bold'),
                                    padx=20, pady=8)
        remove_btn.pack(side=tk.LEFT)

        close_btn = AnimatedButton(button_frame, text="Close", command=dialog.destroy,
                                   bg=self.colors['accent_blue'],
                                   hover_bg=self.colors['accent_hover'],
                                   fg='white', font=('Arial', 9, 'bold'),
                                   padx=20, pady=8)
        close_btn.pack(side=tk.RIGHT)

    def show_activity_history(self):
        """Show activity history with enhanced interface"""
        history = self.config.load_history()
        self.add_log_entry("📊 Viewing activity history", "info")

        if not history:
            messagebox.showinfo("Activity History", "No activity history found.")
            return

        # Enhanced history dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Activity History")
        dialog.geometry("800x600")
        dialog.configure(bg=self.colors['bg_primary'])
        dialog.resizable(True, True)
        dialog.grab_set()
        dialog.transient(self.root)

        # Center dialog
        self.center_dialog(dialog)

        # Main frame with blur effect
        main_frame = BlurredFrame(dialog, bg=self.colors['bg_primary'], blur_strength=3)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        title_label = tk.Label(main_frame,
                               text="📊 Activity History",
                               bg=self.colors['bg_primary'],
                               fg=self.colors['text_primary'],
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 15))

        # Stats
        total_ops = len(history)
        successful = len([h for h in history if h.get("status") == "success"])
        failed = total_ops - successful

        stats_label = tk.Label(main_frame,
                               text=f"📈 Total: {total_ops}  •  ✅ Success: {successful}  •  ❌ Failed: {failed}",
                               bg=self.colors['bg_primary'],
                               fg=self.colors['text_secondary'],
                               font=('Arial', 10))
        stats_label.pack(pady=(0, 15))

        # Treeview for history
        tree_frame = BlurredFrame(main_frame, bg=self.colors['bg_secondary'], blur_strength=2)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        columns = ('Time', 'Action', 'Type', 'Item', 'Status')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)

        # Configure columns
        tree.heading('Time', text='Timestamp')
        tree.heading('Action', text='Action')
        tree.heading('Type', text='Type')
        tree.heading('Item', text='Item Name')
        tree.heading('Status', text='Status')

        tree.column('Time', width=150)
        tree.column('Action', width=100)
        tree.column('Type', width=80)
        tree.column('Item', width=200)
        tree.column('Status', width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        # Pack treeview and scrollbar
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=15)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=15)

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
            item_type = entry.get('item_type', 'folder')
            type_icon = "📁" if item_type == "folder" else "📄"
            item_name = entry.get('item_name', 'Unknown')
            status = entry.get('status', 'Unknown').title()

            # Add status emoji
            if status == 'Success':
                status = '✅ Success'
            elif status == 'Failed':
                status = '❌ Failed'

            tree.insert('', tk.END, values=(timestamp, action, type_icon, item_name, status))

        # Button frame
        button_frame = tk.Frame(main_frame, bg=self.colors['bg_primary'])
        button_frame.pack(fill=tk.X)

        def clear_history():
            if messagebox.askyesno("Clear History", "Clear all activity history?"):
                with open(self.config.history_file, 'w') as f:
                    json.dump([], f)
                dialog.destroy()
                self.add_log_entry("🧹 Activity history cleared", "warning")

        clear_btn = AnimatedButton(button_frame, text="🧹 Clear History", command=clear_history,
                                   bg=self.colors['warning'],
                                   hover_bg='#D97706',
                                   fg='white', font=('Arial', 9, 'bold'),
                                   padx=20, pady=8)
        clear_btn.pack(side=tk.LEFT)

        close_btn = AnimatedButton(button_frame, text="Close", command=dialog.destroy,
                                   bg=self.colors['accent_blue'],
                                   hover_bg=self.colors['accent_hover'],
                                   fg='white', font=('Arial', 9, 'bold'),
                                   padx=20, pady=8)
        close_btn.pack(side=tk.RIGHT)

    def clear_all_data(self):
        """Clear all application data with confirmation"""
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
        """Clear activity log with animation"""

        # Animate clearing
        def clear_with_animation():
            self.activity_log.delete(1.0, tk.END)
            self.add_log_entry("📝 Activity log cleared", "info")

        # Add fade out effect
        original_alpha = self.activity_log.cget('bg')
        self.activity_log.config(bg=self.colors['bg_panel'])
        self.root.after(200, clear_with_animation)
        self.root.after(400, lambda: self.activity_log.config(bg=original_alpha))

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
        """Center window on screen with animation"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def center_dialog(self, dialog):
        """Center dialog on parent with animation"""
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

    def run_in_thread(self, target, *args):
        """Run function in separate thread"""
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()

    def run(self):
        """Start the application with enhanced initialization"""
        try:
            # Show splash screen effect
            self.root.update()

            # Start main loop
            self.root.mainloop()
        except Exception as e:
            print(f"GUI Error: {e}")











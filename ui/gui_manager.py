#!/usr/bin/env python3
"""
STARK File Locker - Enhanced GUI Manager
Dark Mode with proper .locked file behavior and confirmation dialogs
"""

import sys
import os
import json
import secrets
import string
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QLineEdit, QTextEdit, QTabWidget, QFrame,
        QScrollArea, QComboBox, QCheckBox, QSpinBox, QProgressBar,
        QMessageBox, QFileDialog, QListWidget, QListWidgetItem,
        QSplitter, QGroupBox, QGridLayout, QFormLayout, QSlider,
        QButtonGroup, QRadioButton, QSpacerItem, QSizePolicy
    )
    from PyQt6.QtCore import (
        Qt, QThread, pyqtSignal, QTimer, QSize, QRect,
        QPropertyAnimation, QEasingCurve, QParallelAnimationGroup
    )
    from PyQt6.QtGui import (
        QFont, QPixmap, QIcon, QPalette, QColor, QPainter,
        QLinearGradient, QBrush, QPen, QKeySequence, QShortcut,
        QDragEnterEvent, QDropEvent, QResizeEvent
    )
except ImportError as e:
    print(f"PyQt6 import error: {e}")
    print("Please install PyQt6: pip install PyQt6")
    sys.exit(1)

try:
    import pyperclip

    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False
    print("pyperclip not available - clipboard functionality disabled")

from core.config import (
    APP_CONFIG, UI_CONFIG, LANGUAGES, ENCRYPTION_CONFIG,
    TIMED_LOCK_CONFIG, get_text
)
from core.encryption_manager import EncryptionManager


class ModernButton(QPushButton):
    """Enhanced button with modern styling and hover effects"""

    def __init__(self, text: str, button_type: str = 'primary', parent=None):
        super().__init__(text, parent)
        self.button_type = button_type
        self.is_hovered = False
        self.setup_style()

    def setup_style(self):
        """Setup modern button styling"""
        colors = {
            'primary': UI_CONFIG['BUTTON_PRIMARY'],
            'secondary': UI_CONFIG['BUTTON_SECONDARY'],
            'success': UI_CONFIG['BUTTON_SUCCESS'],
            'warning': UI_CONFIG['BUTTON_WARNING'],
            'danger': UI_CONFIG['BUTTON_DANGER']
        }

        base_color = colors.get(self.button_type, colors['primary'])

        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {base_color};
                color: {UI_CONFIG['BUTTON_TEXT']};
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-family: {UI_CONFIG['BUTTON_FONT'][0]};
                font-size: {UI_CONFIG['BUTTON_FONT'][1]}px;
                font-weight: bold;
                min-height: 20px;
            }}
            QPushButton:hover {{
                background-color: {self._darken_color(base_color, 0.1)};
                transform: translateY(-1px);
            }}
            QPushButton:pressed {{
                background-color: {self._darken_color(base_color, 0.2)};
                transform: translateY(0px);
            }}
            QPushButton:disabled {{
                background-color: {UI_CONFIG['BORDER_COLOR']};
                color: {UI_CONFIG['TEXT_MUTED']};
            }}
        """)

    def _darken_color(self, color: str, factor: float) -> str:
        """Darken a hex color by a factor"""
        try:
            color = color.lstrip('#')
            rgb = tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))
            darkened = tuple(max(0, int(c * (1 - factor))) for c in rgb)
            return f"#{darkened[0]:02x}{darkened[1]:02x}{darkened[2]:02x}"
        except:
            return color


class ModernCard(QFrame):
    """Modern card widget with rounded corners and shadow effect"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_style()

    def setup_style(self):
        """Setup card styling"""
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {UI_CONFIG['CARD_COLOR']};
                border: 1px solid {UI_CONFIG['BORDER_COLOR']};
                border-radius: 12px;
                padding: 16px;
            }}
        """)
        self.setFrameStyle(QFrame.Shape.Box)


class DragDropArea(QFrame):
    """Enhanced drag and drop area with visual feedback"""

    files_dropped = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.is_dragging = False
        self.setup_ui()
        self.setup_style()

    def setup_ui(self):
        """Setup drag drop area UI"""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)

        # Icon label
        self.icon_label = QLabel("📁")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setStyleSheet("font-size: 48px;")

        # Text label
        self.text_label = QLabel("Drag & Drop Files/Folders Here")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.text_label.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_SECONDARY']};
            font-size: 16px;
            font-weight: 500;
        """)

        # Subtext
        self.subtext_label = QLabel("or click to browse")
        self.subtext_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtext_label.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_MUTED']};
            font-size: 12px;
        """)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)
        layout.addWidget(self.subtext_label)

    def setup_style(self):
        """Setup drag drop area styling"""
        self.update_style()

    def update_style(self):
        """Update styling based on current state"""
        if self.is_dragging:
            border_color = UI_CONFIG['DROP_ZONE_BORDER']
            bg_color = UI_CONFIG['DROP_ZONE_COLOR']
            border_style = "2px dashed"
        else:
            border_color = UI_CONFIG['BORDER_COLOR']
            bg_color = UI_CONFIG['CARD_COLOR']
            border_style = "2px dashed"

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                border: {border_style} {border_color};
                border-radius: 12px;
                min-height: 200px;
            }}
        """)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.is_dragging = True
            self.update_style()

    def dragLeaveEvent(self, event):
        """Handle drag leave event"""
        self.is_dragging = False
        self.update_style()

    def dropEvent(self, event: QDropEvent):
        """Handle drop event"""
        self.is_dragging = False
        self.update_style()

        files = []
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.exists(file_path):
                files.append(file_path)

        if files:
            self.files_dropped.emit(files)

    def mousePressEvent(self, event):
        """Handle mouse press for file dialog"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.open_file_dialog()

    def open_file_dialog(self):
        """Open file dialog for manual file selection"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Files to Lock/Unlock",
            os.path.expanduser('~'),
            "All Files (*.*)"
        )
        if files:
            self.files_dropped.emit(files)


class PasswordStrengthIndicator(QWidget):
    """Visual password strength indicator"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.strength = 0
        self.setup_ui()

    def setup_ui(self):
        """Setup strength indicator UI"""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        self.bars = []
        for i in range(4):
            bar = QFrame()
            bar.setFixedSize(20, 4)
            bar.setStyleSheet(f"background-color: {UI_CONFIG['BORDER_COLOR']}; border-radius: 2px;")
            self.bars.append(bar)
            layout.addWidget(bar)

        layout.addStretch()

        self.label = QLabel("Enter password")
        self.label.setStyleSheet(f"color: {UI_CONFIG['TEXT_MUTED']}; font-size: 11px;")
        layout.addWidget(self.label)

    def update_strength(self, password: str):
        """Update strength indicator based on password"""
        if not password:
            self.strength = 0
            self.label.setText("Enter password")
        else:
            # Calculate strength
            score = 0
            if len(password) >= 6: score += 1
            if len(password) >= 8: score += 1
            if any(c.isupper() for c in password) and any(c.islower() for c in password): score += 1
            if any(c.isdigit() for c in password): score += 1
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 1

            self.strength = min(4, score)

        # Update visual indicators
        colors = ['#ef4444', '#f59e0b', '#eab308', '#10b981']
        labels = ['Weak', 'Fair', 'Good', 'Strong']

        for i, bar in enumerate(self.bars):
            if i < self.strength:
                color = colors[min(self.strength - 1, 3)]
                bar.setStyleSheet(f"background-color: {color}; border-radius: 2px;")
            else:
                bar.setStyleSheet(f"background-color: {UI_CONFIG['BORDER_COLOR']}; border-radius: 2px;")

        if self.strength > 0:
            self.label.setText(labels[min(self.strength - 1, 3)])
        else:
            self.label.setText("Enter password")


class AdvancedFolderLocker(QMainWindow):
    """Main application window - Dark Mode Only"""

    def __init__(self):
        super().__init__()
        self.encryption_manager = EncryptionManager()
        self.selected_files = []
        self.current_language = 'english'
        self.is_fullscreen = False
        self.normal_geometry = None

        # Initialize UI
        self.setup_ui()
        self.setup_shortcuts()
        self.apply_dark_theme()
        self.setup_responsive_layout()

        # Show welcome message
        self.show_status_message("Ready - Easy to use, no master password required", "success")

    def setup_ui(self):
        """Setup main user interface"""
        self.setWindowTitle(f"{APP_CONFIG['APP_NAME']} v{APP_CONFIG['VERSION']}")
        self.setMinimumSize(*APP_CONFIG['MIN_WINDOW_SIZE'])
        self.resize(1200, 800)

        # Try to set window icon
        self.setup_window_icon()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Header
        self.setup_header(main_layout)

        # Tab widget
        self.setup_tabs(main_layout)

        # Status bar
        self.setup_status_bar()

    def setup_window_icon(self):
        """Setup window icon"""
        icon_paths = [
            os.path.join('assets', 'logo.ico'),
            os.path.join('assets', 'logo.png'),
            os.path.join('assets', 'Advanced Folder Locker.png')
        ]

        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                try:
                    self.setWindowIcon(QIcon(icon_path))
                    break
                except Exception as e:
                    print(f"Could not load icon {icon_path}: {e}")

    def setup_header(self, layout):
        """Setup application header"""
        header_frame = ModernCard()
        header_layout = QHBoxLayout(header_frame)

        # Title
        title_label = QLabel(get_text(self.current_language, 'app_title'))
        title_label.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_COLOR']};
            font-family: {UI_CONFIG['HEADER_FONT'][0]};
            font-size: {UI_CONFIG['HEADER_FONT'][1]}px;
            font-weight: bold;
        """)

        header_layout.addWidget(title_label)
        header_layout.addStretch()

        # Dark mode indicator (no toggle button)
        mode_label = QLabel("🌙 Dark Mode")
        mode_label.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_SECONDARY']};
            font-size: 12px;
            padding: 8px 16px;
            background-color: {UI_CONFIG['CONTENT_COLOR']};
            border-radius: 6px;
        """)
        header_layout.addWidget(mode_label)

        layout.addWidget(header_frame)

    def setup_tabs(self, layout):
        """Setup main tab widget"""
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {UI_CONFIG['BORDER_COLOR']};
                border-radius: 8px;
                background-color: {UI_CONFIG['CARD_COLOR']};
            }}
            QTabBar::tab {{
                background-color: {UI_CONFIG['CONTENT_COLOR']};
                color: {UI_CONFIG['TEXT_COLOR']};
                padding: 12px 24px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: 500;
            }}
            QTabBar::tab:selected {{
                background-color: {UI_CONFIG['PRIMARY_COLOR']};
                color: white;
            }}
            QTabBar::tab:hover {{
                background-color: {UI_CONFIG['HOVER_COLOR']};
            }}
        """)

        # Main tab
        self.main_tab = self.create_main_tab()
        self.tab_widget.addTab(self.main_tab, get_text(self.current_language, 'main_tab'))

        # Settings tab
        self.settings_tab = self.create_settings_tab()
        self.tab_widget.addTab(self.settings_tab, get_text(self.current_language, 'settings_tab'))

        # About tab
        self.about_tab = self.create_about_tab()
        self.tab_widget.addTab(self.about_tab, get_text(self.current_language, 'about_tab'))

        layout.addWidget(self.tab_widget)

    def create_main_tab(self):
        """Create main functionality tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(20)

        # Create splitter for responsive layout
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)

        # Right panel
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)

        # Set splitter proportions
        splitter.setSizes([400, 300])
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)

        layout.addWidget(splitter)

        return tab

    def create_left_panel(self):
        """Create left panel with drag-drop and file list"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(16)

        # Drag and drop area
        self.drag_drop_area = DragDropArea()
        self.drag_drop_area.files_dropped.connect(self.add_files)
        layout.addWidget(self.drag_drop_area)

        # File management buttons
        button_layout = QHBoxLayout()

        self.add_files_btn = ModernButton("📁 Add Files", 'secondary')
        self.add_files_btn.clicked.connect(self.browse_files)
        button_layout.addWidget(self.add_files_btn)

        self.add_folder_btn = ModernButton("📂 Add Folder", 'secondary')
        self.add_folder_btn.clicked.connect(self.browse_folder)
        button_layout.addWidget(self.add_folder_btn)

        self.clear_btn = ModernButton("🗑️ Clear All", 'danger')
        self.clear_btn.clicked.connect(self.clear_files)
        button_layout.addWidget(self.clear_btn)

        layout.addLayout(button_layout)

        # Selected files list
        files_card = ModernCard()
        files_layout = QVBoxLayout(files_card)

        files_header = QLabel("Selected Items")
        files_header.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_COLOR']};
            font-size: 14px;
            font-weight: bold;
            margin-bottom: 8px;
        """)
        files_layout.addWidget(files_header)

        self.files_list = QListWidget()
        self.files_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {UI_CONFIG['BG_COLOR']};
                border: 1px solid {UI_CONFIG['BORDER_COLOR']};
                border-radius: 6px;
                padding: 8px;
                color: {UI_CONFIG['TEXT_COLOR']};
            }}
            QListWidget::item {{
                padding: 8px;
                border-radius: 4px;
                margin: 2px 0;
            }}
            QListWidget::item:selected {{
                background-color: {UI_CONFIG['PRIMARY_COLOR']};
                color: white;
            }}
            QListWidget::item:hover {{
                background-color: {UI_CONFIG['HOVER_COLOR']};
            }}
        """)
        files_layout.addWidget(self.files_list)

        # Files count label
        self.files_count_label = QLabel("0 items selected")
        self.files_count_label.setStyleSheet(f"color: {UI_CONFIG['TEXT_MUTED']}; font-size: 12px;")
        files_layout.addWidget(self.files_count_label)

        layout.addWidget(files_card)

        return panel

    def create_right_panel(self):
        """Create right panel with password and actions"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(16)

        # Password section
        password_card = ModernCard()
        password_layout = QVBoxLayout(password_card)

        password_header = QLabel("Password & Security Options")
        password_header.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_COLOR']};
            font-size: 14px;
            font-weight: bold;
            margin-bottom: 12px;
        """)
        password_layout.addWidget(password_header)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter a strong password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.on_password_changed)
        self.password_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {UI_CONFIG['BG_COLOR']};
                border: 2px solid {UI_CONFIG['BORDER_COLOR']};
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                color: {UI_CONFIG['TEXT_COLOR']};
            }}
            QLineEdit:focus {{
                border-color: {UI_CONFIG['PRIMARY_COLOR']};
            }}
        """)
        password_layout.addWidget(self.password_input)

        # Password strength indicator
        self.password_strength = PasswordStrengthIndicator()
        password_layout.addWidget(self.password_strength)

        # Password options
        options_layout = QHBoxLayout()

        self.show_password_btn = QPushButton("👁️")
        self.show_password_btn.setFixedSize(40, 40)
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.toggled.connect(self.toggle_password_visibility)
        self.show_password_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {UI_CONFIG['CONTENT_COLOR']};
                border: 1px solid {UI_CONFIG['BORDER_COLOR']};
                border-radius: 6px;
                font-size: 16px;
            }}
            QPushButton:hover {{
                background-color: {UI_CONFIG['HOVER_COLOR']};
            }}
        """)
        options_layout.addWidget(self.show_password_btn)

        self.generate_password_btn = ModernButton("🎲 Generate", 'secondary')
        self.generate_password_btn.clicked.connect(self.generate_password)
        options_layout.addWidget(self.generate_password_btn)

        password_layout.addLayout(options_layout)

        # Advanced options
        self.timed_lock_cb = QCheckBox("Timed Lock")
        self.timed_lock_cb.setStyleSheet(f"color: {UI_CONFIG['TEXT_COLOR']};")
        password_layout.addWidget(self.timed_lock_cb)

        self.timed_lock_combo = QComboBox()
        for duration_name, _ in TIMED_LOCK_CONFIG['DURATIONS']:
            self.timed_lock_combo.addItem(duration_name)
        self.timed_lock_combo.setEnabled(False)
        self.timed_lock_cb.toggled.connect(self.timed_lock_combo.setEnabled)
        password_layout.addWidget(self.timed_lock_combo)

        self.double_lock_cb = QCheckBox("Double Lock (Extra Security)")
        self.double_lock_cb.setStyleSheet(f"color: {UI_CONFIG['TEXT_COLOR']};")
        password_layout.addWidget(self.double_lock_cb)

        layout.addWidget(password_card)

        # Action buttons
        actions_card = ModernCard()
        actions_layout = QVBoxLayout(actions_card)

        self.lock_btn = ModernButton("🔒 Lock Selected Items", 'primary')
        self.lock_btn.clicked.connect(self.lock_files)
        actions_layout.addWidget(self.lock_btn)

        self.unlock_btn = ModernButton("🔓 Unlock Selected Items", 'success')
        self.unlock_btn.clicked.connect(self.unlock_files)
        actions_layout.addWidget(self.unlock_btn)

        layout.addWidget(actions_card)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {UI_CONFIG['BORDER_COLOR']};
                border-radius: 6px;
                text-align: center;
                background-color: {UI_CONFIG['BG_COLOR']};
                color: {UI_CONFIG['TEXT_COLOR']};
            }}
            QProgressBar::chunk {{
                background-color: {UI_CONFIG['PRIMARY_COLOR']};
                border-radius: 5px;
            }}
        """)
        layout.addWidget(self.progress_bar)

        layout.addStretch()

        return panel

    def create_settings_tab(self):
        """Create settings tab - Dark Mode Only"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(20)

        # Create scroll area for settings
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        settings_layout.setSpacing(20)

        # Language settings
        lang_card = ModernCard()
        lang_layout = QFormLayout(lang_card)

        lang_header = QLabel("Language Settings")
        lang_header.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_COLOR']};
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 12px;
        """)
        lang_layout.addRow(lang_header)

        self.language_combo = QComboBox()
        for lang_key, lang_data in LANGUAGES.items():
            self.language_combo.addItem(lang_data['name'], lang_key)
        self.language_combo.currentTextChanged.connect(self.change_language)
        lang_layout.addRow("Language:", self.language_combo)

        settings_layout.addWidget(lang_card)

        # Security settings
        security_card = ModernCard()
        security_layout = QFormLayout(security_card)

        security_header = QLabel("Security Settings")
        security_header.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_COLOR']};
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 12px;
        """)
        security_layout.addRow(security_header)

        self.secure_delete_cb = QCheckBox("Secure file deletion")
        self.secure_delete_cb.setChecked(True)
        security_layout.addRow(self.secure_delete_cb)

        self.backup_cb = QCheckBox("Create backups before encryption")
        security_layout.addRow(self.backup_cb)

        settings_layout.addWidget(security_card)

        settings_layout.addStretch()
        scroll.setWidget(settings_widget)
        layout.addWidget(scroll)

        return tab

    def create_about_tab(self):
        """Create about tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        # App info card
        about_card = ModernCard()
        about_layout = QVBoxLayout(about_card)
        about_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.setSpacing(16)

        # App icon/logo
        icon_label = QLabel("🔐")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("font-size: 64px;")
        about_layout.addWidget(icon_label)

        # App name
        name_label = QLabel(APP_CONFIG['APP_NAME'])
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label.setStyleSheet(f"""
            color: {UI_CONFIG['TEXT_COLOR']};
            font-size: 24px;
            font-weight: bold;
        """)
        about_layout.addWidget(name_label)

        # Version
        version_label = QLabel(f"Version {APP_CONFIG['VERSION']}")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_label.setStyleSheet(f"color: {UI_CONFIG['TEXT_MUTED']}; font-size: 14px;")
        about_layout.addWidget(version_label)

        # Description
        desc_label = QLabel(APP_CONFIG['DESCRIPTION'])
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet(f"color: {UI_CONFIG['TEXT_SECONDARY']}; font-size: 12px; margin: 16px;")
        about_layout.addWidget(desc_label)

        # Features list
        features_label = QLabel("""
        ✨ Features:
        • Modern PyQt6 interface with dark theme
        • Drag & drop functionality
        • Multi-language support (English, German, French)
        • AES-256 encryption with secure key derivation
        • Proper .locked file behavior
        • Timed lock and double lock options
        • Batch file processing
        • Secure file deletion
        • F11 fullscreen toggle
        • Smart error handling with confirmation dialogs
        """)
        features_label.setStyleSheet(f"color: {UI_CONFIG['TEXT_COLOR']}; font-size: 11px; line-height: 1.4;")
        about_layout.addWidget(features_label)

        # Contact info
        contact_label = QLabel(f"Contact: {APP_CONFIG['DEVELOPER_EMAIL']}")
        contact_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        contact_label.setStyleSheet(f"color: {UI_CONFIG['TEXT_MUTED']}; font-size: 10px;")
        about_layout.addWidget(contact_label)

        layout.addWidget(about_card)

        return tab

    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = self.statusBar()
        self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {UI_CONFIG['CONTENT_COLOR']};
                color: {UI_CONFIG['TEXT_COLOR']};
                border-top: 1px solid {UI_CONFIG['BORDER_COLOR']};
                padding: 4px;
            }}
        """)

        # Fullscreen hint
        self.fullscreen_label = QLabel("Press F11 for fullscreen")
        self.fullscreen_label.setStyleSheet(f"color: {UI_CONFIG['TEXT_MUTED']}; font-size: 11px;")
        self.status_bar.addPermanentWidget(self.fullscreen_label)

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        # F11 for fullscreen toggle
        self.fullscreen_shortcut = QShortcut(QKeySequence("F11"), self)
        self.fullscreen_shortcut.activated.connect(self.toggle_fullscreen)

        # Ctrl+O for open files
        self.open_shortcut = QShortcut(QKeySequence("Ctrl+O"), self)
        self.open_shortcut.activated.connect(self.browse_files)

        # Ctrl+L for lock
        self.lock_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.lock_shortcut.activated.connect(self.lock_files)

        # Ctrl+U for unlock
        self.unlock_shortcut = QShortcut(QKeySequence("Ctrl+U"), self)
        self.unlock_shortcut.activated.connect(self.unlock_files)

    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        # Update main window background
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {UI_CONFIG['BG_COLOR']};
                color: {UI_CONFIG['TEXT_COLOR']};
            }}
            QWidget {{
                background-color: {UI_CONFIG['BG_COLOR']};
                color: {UI_CONFIG['TEXT_COLOR']};
            }}
        """)

    def setup_responsive_layout(self):
        """Setup responsive layout behavior"""
        # Connect resize event
        self.resizeEvent = self.on_window_resize

    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        if self.is_fullscreen:
            # Exit fullscreen
            self.showNormal()
            if self.normal_geometry:
                self.setGeometry(self.normal_geometry)
            self.is_fullscreen = False
            self.fullscreen_label.setText("Press F11 for fullscreen")
        else:
            # Enter fullscreen
            self.normal_geometry = self.geometry()
            self.showFullScreen()
            self.is_fullscreen = True
            self.fullscreen_label.setText("Press F11 to exit fullscreen")

    def on_window_resize(self, event: QResizeEvent):
        """Handle window resize for responsive layout"""
        # Call the original resize event
        super().resizeEvent(event)

    def add_files(self, file_paths: List[str]):
        """Add files to the selection list"""
        for file_path in file_paths:
            if file_path not in self.selected_files:
                self.selected_files.append(file_path)

                # Add to list widget
                item = QListWidgetItem()
                if os.path.isdir(file_path):
                    item.setText(f"📁 {os.path.basename(file_path)}")
                elif file_path.endswith('.locked'):
                    item.setText(f"🔒 {os.path.basename(file_path)}")
                else:
                    item.setText(f"📄 {os.path.basename(file_path)}")
                item.setData(Qt.ItemDataRole.UserRole, file_path)
                self.files_list.addItem(item)

        self.update_files_count()

    def browse_files(self):
        """Browse for files to add"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Files to Lock/Unlock",
            os.path.expanduser('~'),
            "All Files (*.*)"
        )
        if files:
            self.add_files(files)

    def browse_folder(self):
        """Browse for folder to add"""
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to Lock/Unlock",
            os.path.expanduser('~')
        )
        if folder:
            self.add_files([folder])

    def clear_files(self):
        """Clear all selected files"""
        self.selected_files.clear()
        self.files_list.clear()
        self.update_files_count()

    def update_files_count(self):
        """Update the files count label"""
        count = len(self.selected_files)
        if count == 0:
            self.files_count_label.setText("0 items selected")
        elif count == 1:
            self.files_count_label.setText("1 item selected")
        else:
            self.files_count_label.setText(f"{count} items selected")

    def on_password_changed(self, text: str):
        """Handle password input changes"""
        self.password_strength.update_strength(text)

    def toggle_password_visibility(self, checked: bool):
        """Toggle password visibility"""
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_btn.setText("🙈")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_btn.setText("👁️")

    def generate_password(self):
        """Generate a strong password"""
        password = self.encryption_manager.generate_strong_password(16)
        self.password_input.setText(password)

        if CLIPBOARD_AVAILABLE:
            try:
                pyperclip.copy(password)
                self.show_status_message("Password generated and copied to clipboard", "success")
            except:
                self.show_status_message("Password generated", "success")
        else:
            self.show_status_message("Password generated", "success")

    def show_confirmation_dialog(self, title: str, message: str) -> bool:
        """Show confirmation dialog and return user choice"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Question)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg_box.setDefaultButton(QMessageBox.StandardButton.No)

        result = msg_box.exec()
        return result == QMessageBox.StandardButton.Yes

    def lock_files(self):
        """Lock selected files with confirmation dialog"""
        # Validate inputs
        if not self.selected_files:
            self.show_error_message(
                get_text(self.current_language, 'no_files_selected'),
                "Please select files or folders to lock first."
            )
            return

        password = self.password_input.text().strip()
        if not password:
            self.show_error_message(
                get_text(self.current_language, 'empty_password'),
                "Please enter a password to encrypt your files."
            )
            self.password_input.setFocus()
            return

        # Validate password strength
        is_valid, msg = self.encryption_manager.validate_password(password)
        if not is_valid:
            self.show_error_message("Weak Password", msg)
            self.password_input.setFocus()
            return

        # Show confirmation dialog
        if not self.show_confirmation_dialog(
                get_text(self.current_language, 'confirm_delete'),
                get_text(self.current_language, 'delete_original_warning')
        ):
            return

        # Get options
        timed_lock = None
        if self.timed_lock_cb.isChecked():
            duration_name = self.timed_lock_combo.currentText()
            for name, minutes in TIMED_LOCK_CONFIG['DURATIONS']:
                if name == duration_name:
                    timed_lock = minutes
                    break

        double_lock = self.double_lock_cb.isChecked()

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(self.selected_files))
        self.progress_bar.setValue(0)

        # Process files
        successful = 0
        failed = 0
        errors = []

        for i, file_path in enumerate(self.selected_files):
            try:
                # Skip already locked files
                if file_path.endswith('.locked'):
                    failed += 1
                    errors.append(f"{os.path.basename(file_path)}: File is already locked")
                    continue

                if os.path.isfile(file_path):
                    success, msg = self.encryption_manager.encrypt_file(
                        file_path, password, timed_lock, double_lock
                    )
                elif os.path.isdir(file_path):
                    success, msg = self.encryption_manager.encrypt_folder(
                        file_path, password, timed_lock, double_lock
                    )
                else:
                    success = False
                    msg = "Invalid file path"

                if success:
                    successful += 1
                else:
                    failed += 1
                    errors.append(f"{os.path.basename(file_path)}: {msg}")

            except Exception as e:
                failed += 1
                errors.append(f"{os.path.basename(file_path)}: {str(e)}")

            self.progress_bar.setValue(i + 1)
            QApplication.processEvents()

        # Hide progress
        self.progress_bar.setVisible(False)

        # Show results
        if successful > 0 and failed == 0:
            self.show_status_message(f"Successfully locked {successful} items", "success")
            self.clear_files()
            self.password_input.clear()
        elif successful > 0 and failed > 0:
            error_details = "\n".join(errors[:5])  # Show first 5 errors
            if len(errors) > 5:
                error_details += f"\n... and {len(errors) - 5} more errors"
            self.show_warning_message(
                f"Partially completed: {successful} successful, {failed} failed",
                error_details
            )
        else:
            error_details = "\n".join(errors[:5])
            if len(errors) > 5:
                error_details += f"\n... and {len(errors) - 5} more errors"
            self.show_error_message("Locking failed", error_details)

    def unlock_files(self):
        """Unlock selected files with confirmation dialog"""
        # Validate inputs
        if not self.selected_files:
            self.show_error_message(
                get_text(self.current_language, 'no_files_selected'),
                "Please select locked files to unlock first."
            )
            return

        password = self.password_input.text().strip()
        if not password:
            self.show_error_message(
                get_text(self.current_language, 'empty_password'),
                "Please enter the password to decrypt your files."
            )
            self.password_input.setFocus()
            return

        # Filter locked files
        locked_files = [f for f in self.selected_files if f.endswith('.locked')]
        if not locked_files:
            self.show_error_message(
                "No Locked Files",
                "Please select files with .locked extension to unlock."
            )
            return

        # Show confirmation dialog
        if not self.show_confirmation_dialog(
                get_text(self.current_language, 'confirm_delete'),
                get_text(self.current_language, 'delete_locked_warning')
        ):
            return

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(locked_files))
        self.progress_bar.setValue(0)

        # Process files
        successful = 0
        failed = 0
        errors = []

        for i, file_path in enumerate(locked_files):
            try:
                # Check if it's a folder or file based on metadata
                metadata = self.encryption_manager._get_file_metadata(file_path)
                if metadata and 'folder_archive' in metadata.get('original_name', ''):
                    success, msg = self.encryption_manager.decrypt_folder(file_path, password)
                else:
                    success, msg = self.encryption_manager.decrypt_file(file_path, password)

                if success:
                    successful += 1
                else:
                    failed += 1
                    errors.append(f"{os.path.basename(file_path)}: {msg}")

            except Exception as e:
                failed += 1
                errors.append(f"{os.path.basename(file_path)}: {str(e)}")

            self.progress_bar.setValue(i + 1)
            QApplication.processEvents()

        # Hide progress
        self.progress_bar.setVisible(False)

        # Show results
        if successful > 0 and failed == 0:
            self.show_status_message(f"Successfully unlocked {successful} items", "success")
            self.clear_files()
            self.password_input.clear()
        elif successful > 0 and failed > 0:
            error_details = "\n".join(errors[:5])
            if len(errors) > 5:
                error_details += f"\n... and {len(errors) - 5} more errors"
            self.show_warning_message(
                f"Partially completed: {successful} successful, {failed} failed",
                error_details
            )
        else:
            error_details = "\n".join(errors[:5])
            if len(errors) > 5:
                error_details += f"\n... and {len(errors) - 5} more errors"
            self.show_error_message("Unlocking failed", error_details)

    def change_language(self, language_name: str):
        """Change application language"""
        for lang_key, lang_data in LANGUAGES.items():
            if lang_data['name'] == language_name:
                self.current_language = lang_key
                self.update_ui_text()
                self.show_status_message(f"Language changed to {language_name}", "info")
                break

    def update_ui_text(self):
        """Update all UI text with current language"""
        # Update window title
        self.setWindowTitle(get_text(self.current_language, 'app_title'))

        # Update tab titles
        self.tab_widget.setTabText(0, get_text(self.current_language, 'main_tab'))
        self.tab_widget.setTabText(1, get_text(self.current_language, 'settings_tab'))
        self.tab_widget.setTabText(2, get_text(self.current_language, 'about_tab'))

    def show_status_message(self, message: str, msg_type: str = "info"):
        """Show status message in status bar"""
        colors = {
            'info': UI_CONFIG['INFO_COLOR'],
            'success': UI_CONFIG['SUCCESS_COLOR'],
            'warning': UI_CONFIG['WARNING_COLOR'],
            'error': UI_CONFIG['DANGER_COLOR']
        }

        color = colors.get(msg_type, colors['info'])
        self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {UI_CONFIG['CONTENT_COLOR']};
                color: {color};
                border-top: 1px solid {UI_CONFIG['BORDER_COLOR']};
                padding: 4px;
            }}
        """)

        self.status_bar.showMessage(message, 5000)  # Show for 5 seconds

        # Reset color after message
        QTimer.singleShot(5000, lambda: self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {UI_CONFIG['CONTENT_COLOR']};
                color: {UI_CONFIG['TEXT_COLOR']};
                border-top: 1px solid {UI_CONFIG['BORDER_COLOR']};
                padding: 4px;
            }}
        """))

    def show_error_message(self, title: str, message: str):
        """Show error message dialog"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()

    def show_warning_message(self, title: str, message: str):
        """Show warning message dialog"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()

    def show_info_message(self, title: str, message: str):
        """Show info message dialog"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Information)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()


def main():
    """Main function to run the application"""
    app = QApplication(sys.argv)

    # Set application properties
    app.setApplicationName(APP_CONFIG['APP_NAME'])
    app.setApplicationVersion(APP_CONFIG['VERSION'])
    app.setOrganizationName(APP_CONFIG['AUTHOR'])

    # Create and show main window
    window = AdvancedFolderLocker()
    window.show()

    # Run application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()








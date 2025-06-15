#!/usr/bin/env python3
"""
STARK File Locker - Enhanced Configuration Settings
Dark Mode Only - Light Mode completely removed
"""

import os
from pathlib import Path

# Application Configuration
APP_CONFIG = {
    'APP_NAME': 'Advanced Folder Locker',
    'VERSION': '3.0.0',
    'AUTHOR': 'Enhanced Assistant',
    'DESCRIPTION': 'Advanced file and folder encryption tool with modern dark interface and comprehensive features',
    'WINDOW_SIZE': '1200x800',
    'MIN_WINDOW_SIZE': (1000, 700),
    'DEFAULT_GEOMETRY': '1200x800+100+100',
    'DEVELOPER_EMAIL': 'othmanmuhammad.personal@gmail.com'
}

# Theme Configuration - DARK MODE ONLY
DARK_THEME = {
    'BG_COLOR': '#0f172a',
    'HEADER_COLOR': '#1e40af',
    'CONTENT_COLOR': '#1e293b',
    'PRIMARY_COLOR': '#3b82f6',
    'SECONDARY_COLOR': '#1d4ed8',
    'SUCCESS_COLOR': '#10b981',
    'WARNING_COLOR': '#f59e0b',
    'DANGER_COLOR': '#ef4444',
    'INFO_COLOR': '#3b82f6',
    'TEXT_COLOR': '#f8fafc',
    'TEXT_SECONDARY': '#cbd5e1',
    'TEXT_MUTED': '#94a3b8',
    'CARD_COLOR': '#334155',
    'BORDER_COLOR': '#475569',
    'HOVER_COLOR': '#475569',
    'DROP_ZONE_COLOR': '#1e293b',
    'DROP_ZONE_BORDER': '#3b82f6',
    'BUTTON_TEXT': '#ffffff'
}

# UI Configuration - Always Dark Mode
UI_CONFIG = DARK_THEME.copy()

# Button Colors
UI_CONFIG.update({
    'BUTTON_PRIMARY': '#3b82f6',
    'BUTTON_SECONDARY': '#6b7280',
    'BUTTON_SUCCESS': '#10b981',
    'BUTTON_WARNING': '#f59e0b',
    'BUTTON_DANGER': '#ef4444',

    # Fonts
    'DEFAULT_FONT': ('Segoe UI', 10),
    'HEADER_FONT': ('Segoe UI', 20, 'bold'),
    'TITLE_FONT': ('Segoe UI', 16, 'bold'),
    'SUBTITLE_FONT': ('Segoe UI', 12),
    'BUTTON_FONT': ('Segoe UI', 11, 'bold'),
    'MONOSPACE_FONT': ('Consolas', 10),

    # Animation Settings
    'ANIMATION_ENABLED': False,
})

# Enhanced Encryption Configuration
ENCRYPTION_CONFIG = {
    'DEFAULT_METHOD': 'AES-256',
    'SUPPORTED_METHODS': ['AES-256', 'AES-128'],
    'KEY_ITERATIONS': 100000,
    'SALT_LENGTH': 32,
    'CHUNK_SIZE': 64 * 1024,  # 64KB
    'MIN_PASSWORD_LENGTH': 6,
    'LOCKED_EXTENSION': '.locked',
    'METADATA_EXTENSION': '.lockinfo',
    'BACKUP_EXTENSION': '.backup',
    'DOUBLE_LOCK_ENABLED': True,
    'FAKE_UNLOCK_THRESHOLD': 10,
    'SECURE_DELETE_PASSES': 3
}

# Comprehensive File Type Configuration
FILE_TYPES = {
    'DOCUMENTS': {
        'extensions': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
        'description': 'Document Files',
        'icon': '📄'
    },
    'IMAGES': {
        'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp'],
        'description': 'Image Files',
        'icon': '🖼️'
    },
    'VIDEOS': {
        'extensions': ['.mp4', '.mkv', '.avi', '.mov', '.wmv'],
        'description': 'Video Files',
        'icon': '🎥'
    },
    'AUDIO': {
        'extensions': ['.mp3', '.wav', '.aac', '.flac', '.ogg'],
        'description': 'Audio Files',
        'icon': '🎵'
    },
    'CODE': {
        'extensions': ['.py', '.js', '.html', '.css', '.php', '.java', '.c', '.cpp'],
        'description': 'Code/Script Files',
        'icon': '💻'
    },
    'ARCHIVES': {
        'extensions': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        'description': 'Archive Files',
        'icon': '📦'
    },
    'EXECUTABLES': {
        'extensions': ['.exe', '.msi', '.bat', '.sh', '.apk', '.app'],
        'description': 'Executable Files',
        'icon': '⚙️'
    }
}

# Multi-language Support
LANGUAGES = {
    'english': {
        'name': 'English',
        'code': 'en',
        'texts': {
            'app_title': 'Advanced Folder Locker',
            'welcome': 'Welcome',
            'drag_drop': 'Drag & Drop Files/Folders Here',
            'selected_items': 'Selected Items',
            'password_placeholder': 'Enter a strong password',
            'lock_button': 'Lock Selected Items',
            'unlock_button': 'Unlock Selected Items',
            'generate_password': 'Generate Strong Password',
            'password_manager': 'Password Manager',
            'view_locked': 'View Locked Items',
            'settings': 'Settings',
            'about': 'About',
            'emergency_unlock': 'Emergency Unlock',
            'lock_all': 'Lock All',
            'double_lock': 'Double Lock',
            'timed_lock': 'Timed Lock',
            'clear_evidence': 'Clear Evidence',
            'stealth_mode': 'Stealth Mode',
            'fake_unlock': 'Fake Unlock System',
            'main_tab': 'Main',
            'settings_tab': 'Settings',
            'about_tab': 'About',
            'language_settings': 'Language Settings',
            'security_settings': 'Security Settings',
            'performance_settings': 'Performance Settings',
            'add_files': 'Add Files',
            'add_folder': 'Add Folder',
            'clear_all': 'Clear All',
            'password_security': 'Password & Security Options',
            'duration': 'Duration',
            'ready': 'Ready - Easy to use, no master password required',
            'items_selected': 'items selected',
            'no_files_selected': 'No files selected',
            'empty_password': 'Password cannot be empty',
            'error': 'Error',
            'warning': 'Warning',
            'success': 'Success',
            'info': 'Information',
            'fullscreen_mode': 'Press F11 to exit fullscreen',
            'normal_mode': 'Press F11 for fullscreen',
            'confirm_delete': 'Confirm File Deletion',
            'delete_original_warning': 'This will permanently delete the original file after encryption. Continue?',
            'delete_locked_warning': 'This will permanently delete the .locked file after decryption. Continue?'
        }
    },
    'german': {
        'name': 'Deutsch',
        'code': 'de',
        'texts': {
            'app_title': 'Erweiterte Ordner-Sperre',
            'welcome': 'Willkommen',
            'drag_drop': 'Dateien/Ordner hier hinziehen',
            'selected_items': 'Ausgewählte Elemente',
            'password_placeholder': 'Starkes Passwort eingeben',
            'lock_button': 'Ausgewählte Elemente sperren',
            'unlock_button': 'Ausgewählte Elemente entsperren',
            'generate_password': 'Starkes Passwort generieren',
            'password_manager': 'Passwort-Manager',
            'view_locked': 'Gesperrte Elemente anzeigen',
            'settings': 'Einstellungen',
            'about': 'Über',
            'emergency_unlock': 'Notfall-Entsperrung',
            'lock_all': 'Alle sperren',
            'double_lock': 'Doppelsperre',
            'timed_lock': 'Zeitsperre',
            'clear_evidence': 'Beweise löschen',
            'stealth_mode': 'Stealth-Modus',
            'fake_unlock': 'Fake-Entsperr-System',
            'main_tab': 'Hauptbereich',
            'settings_tab': 'Einstellungen',
            'about_tab': 'Über',
            'language_settings': 'Spracheinstellungen',
            'security_settings': 'Sicherheitseinstellungen',
            'performance_settings': 'Leistungseinstellungen',
            'add_files': 'Dateien hinzufügen',
            'add_folder': 'Ordner hinzufügen',
            'clear_all': 'Alle löschen',
            'password_security': 'Passwort & Sicherheitsoptionen',
            'duration': 'Dauer',
            'ready': 'Bereit - Einfach zu verwenden, kein Master-Passwort erforderlich',
            'items_selected': 'Elemente ausgewählt',
            'no_files_selected': 'Keine Dateien ausgewählt',
            'empty_password': 'Passwort darf nicht leer sein',
            'error': 'Fehler',
            'warning': 'Warnung',
            'success': 'Erfolg',
            'info': 'Information',
            'fullscreen_mode': 'F11 drücken um Vollbild zu verlassen',
            'normal_mode': 'F11 für Vollbild drücken',
            'confirm_delete': 'Datei-Löschung bestätigen',
            'delete_original_warning': 'Dies wird die ursprüngliche Datei nach der Verschlüsselung dauerhaft löschen. Fortfahren?',
            'delete_locked_warning': 'Dies wird die .locked-Datei nach der Entschlüsselung dauerhaft löschen. Fortfahren?'
        }
    },
    'french': {
        'name': 'Français',
        'code': 'fr',
        'texts': {
            'app_title': 'Verrouillage de Dossiers Avancé',
            'welcome': 'Bienvenue',
            'drag_drop': 'Glisser-déposer fichiers/dossiers ici',
            'selected_items': 'Éléments sélectionnés',
            'password_placeholder': 'Entrez un mot de passe fort',
            'lock_button': 'Verrouiller les éléments sélectionnés',
            'unlock_button': 'Déverrouiller les éléments sélectionnés',
            'generate_password': 'Générer un mot de passe fort',
            'password_manager': 'Gestionnaire de mots de passe',
            'view_locked': 'Voir les éléments verrouillés',
            'settings': 'Paramètres',
            'about': 'À propos',
            'emergency_unlock': 'Déverrouillage d\'urgence',
            'lock_all': 'Tout verrouiller',
            'double_lock': 'Double verrouillage',
            'timed_lock': 'Verrouillage temporisé',
            'clear_evidence': 'Effacer les preuves',
            'stealth_mode': 'Mode furtif',
            'fake_unlock': 'Système de faux déverrouillage',
            'main_tab': 'Principal',
            'settings_tab': 'Paramètres',
            'about_tab': 'À propos',
            'language_settings': 'Paramètres de langue',
            'security_settings': 'Paramètres de sécurité',
            'performance_settings': 'Paramètres de performance',
            'add_files': 'Ajouter des fichiers',
            'add_folder': 'Ajouter un dossier',
            'clear_all': 'Tout effacer',
            'password_security': 'Mot de passe et options de sécurité',
            'duration': 'Durée',
            'ready': 'Prêt - Facile à utiliser, aucun mot de passe maître requis',
            'items_selected': 'éléments sélectionnés',
            'no_files_selected': 'Aucun fichier sélectionné',
            'empty_password': 'Le mot de passe ne peut pas être vide',
            'error': 'Erreur',
            'warning': 'Avertissement',
            'success': 'Succès',
            'info': 'Information',
            'fullscreen_mode': 'Appuyez sur F11 pour quitter le plein écran',
            'normal_mode': 'Appuyez sur F11 pour le plein écran',
            'confirm_delete': 'Confirmer la suppression du fichier',
            'delete_original_warning': 'Cela supprimera définitivement le fichier original après le chiffrement. Continuer?',
            'delete_locked_warning': 'Cela supprimera définitivement le fichier .locked après le déchiffrement. Continuer?'
        }
    }
}

# File Dialog Configuration
DIALOG_CONFIG = {
    'FILE_TYPES': [
        ("All Files", "*.*"),
        ("Documents", "*.pdf *.doc *.docx *.txt *.rtf *.odt"),
        ("Images", "*.jpg *.jpeg *.png *.gif *.bmp *.svg *.webp"),
        ("Videos", "*.mp4 *.mkv *.avi *.mov *.wmv"),
        ("Audio", "*.mp3 *.wav *.aac *.flac *.ogg"),
        ("Code Files", "*.py *.js *.html *.css *.php *.java *.c *.cpp"),
        ("Archives", "*.zip *.rar *.7z *.tar *.gz"),
        ("Executables", "*.exe *.msi *.bat *.sh *.apk *.app"),
        ("Locked Files", "*.locked")
    ],
    'INITIAL_DIR': os.path.expanduser('~'),
    'TITLE_SELECT_FILES': 'Select Files to Lock/Unlock',
    'TITLE_SELECT_FOLDER': 'Select Folder to Lock/Unlock',
    'TITLE_BACKUP_LOCATION': 'Select Backup Location'
}

# Timed Lock Configuration
TIMED_LOCK_CONFIG = {
    'ENABLED': True,
    'DURATIONS': [
        ('1 minute', 1),
        ('1 hour', 60),
        ('1 day', 1440),
        ('1 week', 10080),
        ('1 month', 43200),
        ('1 year', 525600),
        ('100 years', 52560000)
    ],
    'DEFAULT_DURATION': '1 hour'
}

# Important File Keywords
IMPORTANT_FILE_KEYWORDS = [
    'bank', 'banking', 'password', 'passwords', 'secret', 'secrets',
    'private', 'confidential', 'important', 'money', 'finance', 'financial',
    'personal', 'tax', 'taxes', 'credit', 'card', 'account', 'accounts',
    'wallet', 'crypto', 'bitcoin', 'investment', 'insurance', 'legal',
    'contract', 'will', 'testament', 'medical', 'health', 'ssn', 'social'
]


def get_text(language: str, key: str, default: str = None) -> str:
    """Get localized text"""
    if language in LANGUAGES and key in LANGUAGES[language]['texts']:
        return LANGUAGES[language]['texts'][key]
    elif 'english' in LANGUAGES and key in LANGUAGES['english']['texts']:
        return LANGUAGES['english']['texts'][key]
    else:
        return default or key


def is_important_file(filename: str) -> bool:
    """Check if file contains important keywords"""
    filename_lower = filename.lower()
    return any(keyword in filename_lower for keyword in IMPORTANT_FILE_KEYWORDS)


def create_directories():
    """Create necessary directories"""
    directories = [
        os.path.join(os.path.expanduser('~'), 'FolderLocker_Backups'),
        os.path.join(os.path.expanduser('~'), '.folderlocker_logs'),
        os.path.join(os.path.expanduser('~'), '.folderlocker_temp')
    ]

    for directory in directories:
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not create directory {directory}: {e}")


# Initialize directories on import
create_directories()











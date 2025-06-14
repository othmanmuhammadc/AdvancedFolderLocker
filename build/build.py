import PyInstaller.__main__
import os


def build_executable():
    """Build standalone executable"""

    PyInstaller.__main__.run([
        'main.py',
        '--onefile',
        '--windowed',
        '--name=AdvancedFolderLocker',
        '--icon=assets/icon.ico',
        '--add-data=assets;assets',
        '--clean',
        '--noconfirm'
        '--icon=assets/icon.ico',
        '--add-data=assets;assets',
    ])

    print("✅ Build completed successfully!")
    print("📁 Executable created in 'dist' folder")


if __name__ == "__main__":
    build_executable()






import os
import sys
import shutil
import zipfile
import subprocess

print("==================================================")
print("   Aegis AV - Windows FOSS Build Compiler")
print("==================================================")
print()

# 1. Install pyinstaller if not present
try:
    import PyInstaller
    print("[INFO] PyInstaller is already installed.")
except ImportError:
    print("[INFO] Installing PyInstaller...")
    try:
        subprocess.run(["pip", "install", "pyinstaller"], check=True)
    except Exception:
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
        except Exception as e:
            print(f"[WARNING] Could not install PyInstaller automatically: {e}")
            print("Please ensure pyinstaller is installed in your python environment.")

# 2. Execute PyInstaller build command
print("[INFO] Compiling application binary with PyInstaller...")
build_cmd = [
    "pyinstaller",
    "--noconfirm",
    "--onedir",
    "--windowed",
    "--icon=icon.ico",
    "--add-data=web;web",
    "--add-data=rules;rules",
    "main.py"
]
print(f"Running: {' '.join(build_cmd)}")
subprocess.run(build_cmd, check=True)

# 3. Post-build structure adjustments
dist_dir = os.path.join("dist", "main")
target_exe = os.path.join(dist_dir, "main.exe")
new_exe = os.path.join(dist_dir, "AegisAV.exe")

if os.path.exists(target_exe):
    os.rename(target_exe, new_exe)
    print(f"[INFO] Successfully compiled and renamed executable to: {new_exe}")
else:
    print("[ERROR] Compilation output main.exe was not found!")
    sys.exit(1)

# Copy icon to dist directory for shortcuts
shutil.copy("icon.ico", dist_dir)

# 4. Create an automatic Shortcut Creator helper script in the packaged folder
shortcut_helper_content = """@echo off
echo ==================================================
echo   Aegis AV - Start Menu Shortcut Setup
echo ==================================================
echo.
echo Creating Start Menu shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$WshShell = New-Object -ComObject WScript.Shell; $ShortcutPath = Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs\\Aegis AV.lnk'; $Shortcut = $WshShell.CreateShortcut($ShortcutPath); $Shortcut.TargetPath = '%~dp0AegisAV.exe'; $Shortcut.WorkingDirectory = '%~dp0'; $Shortcut.Description = 'Aegis AV Security Suite'; $Shortcut.IconLocation = '%~dp0icon.ico'; $Shortcut.Save(); Write-Output 'Start Menu shortcut created successfully!'"
echo.
echo Launching Aegis AV...
start "" "%~dp0AegisAV.exe"
echo.
pause
"""
with open(os.path.join(dist_dir, "SetupShortcut.bat"), "w") as f:
    f.write(shortcut_helper_content)
print("[INFO] Created 'SetupShortcut.bat' helper script in distribution folder.")

# 5. Pack the entire build folder into a single ZIP file for releases
zip_name = "AegisAV-Windows.zip"
print(f"[INFO] Archiving distribution folder to {zip_name}...")

if os.path.exists(zip_name):
    os.remove(zip_name)

with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(dist_dir):
        for file in files:
            file_path = os.path.join(root, file)
            # Add file keeping relative path under aegis-av/
            arcname = os.path.join("aegis-av", os.path.relpath(file_path, dist_dir))
            zipf.write(file_path, arcname)

print()
print(f"==================================================")
print(f"   Success! Build archived to: {zip_name}")
print(f"   You can upload this ZIP directly to GitHub Releases!")
print(f"==================================================")

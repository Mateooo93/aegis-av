@echo off
echo ============================================
echo    Aegis AV - Installation Script
echo ============================================
echo.
echo Installing Python dependencies...
pip install -r requirements.txt
echo.
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Some packages may have failed to install.
    echo yara-python can be tricky on Windows. Trying alternative...
    pip install customtkinter psutil watchdog pefile requests Pillow
    echo.
    echo If yara-python failed, Aegis will still work without YARA scanning.
    echo To install yara-python manually, try:
    echo   pip install yara-python
    echo Or download pre-built wheel from: https://github.com/VirusTotal/yara-python/releases
)
echo.
echo Creating Start Menu shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0create_shortcut.ps1"
echo.
echo ============================================
echo    Installation Complete!
echo    Run: python main.py
echo ============================================
pause

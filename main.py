"""
Aegis AV - Primary Entry Point
Starts the security suite application, initializes logger, and handles dependency imports.
"""

import os
import sys
import logging
import threading

# Set application working directory to current path
APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

from aegis.config import logger

def check_dependencies():
    """Verify that all core libraries are installed correctly."""
    missing = []
    
    try:
        import fastapi
    except ImportError:
        missing.append("fastapi")
        
    try:
        import uvicorn
    except ImportError:
        missing.append("uvicorn")
        
    try:
        import webview
    except ImportError:
        missing.append("pywebview")
        
    try:
        import psutil
    except ImportError:
        missing.append("psutil")
        
    try:
        import watchdog
    except ImportError:
        missing.append("watchdog")
        
    try:
        import pefile
    except ImportError:
        missing.append("pefile")
        
    try:
        import PIL
    except ImportError:
        missing.append("pillow")
        
    try:
        import yara
    except ImportError:
        # YARA is optional (gracefully falls back if missing)
        logger.warning("yara-python is missing. Signature scanning is disabled.")
        
    if missing:
        print("="*60)
        print("[!] Missing Dependencies!")
        print("="*60)
        print("The following packages are required but not installed:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nPlease run the installer to resolve this:")
        print("  install.bat")
        print("\nOr manually run:")
        print("  pip install -r requirements.txt")
        print("="*60)
        sys.exit(1)

def main():
    logger.info("Initializing Aegis AV Security Suite (Native Desktop)...")
    
    # Verify core environment
    check_dependencies()
    
    import uvicorn
    import webview
    import time
    
    try:
        # Start high-performance uvicorn web server inside background thread
        def run_server():
            try:
                # Use warning log level to keep uvicorn logs clean
                uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False, log_level="warning")
            except Exception as e:
                logger.critical("Web service thread crashed: %s", e)
                
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Allow FastAPI server to bind to port before native window launch
        time.sleep(1.0)
        
        # Create beautiful, borderless, hardware-accelerated standalone native window
        logger.info("Launching standalone Aegis AV Desktop App...")
        webview.create_window(
            title="Aegis AV Security Suite",
            url="http://127.0.0.1:8000/",
            width=1200,
            height=750,
            min_size=(1000, 650),
            resizable=True
        )
        webview.start()
        
    except Exception as e:
        logger.critical("Fatal exception in main web server thread: %s", e, exc_info=True)
        print(f"\n[FATAL ERROR] {e}\nSee logs for details.")

if __name__ == "__main__":
    main()

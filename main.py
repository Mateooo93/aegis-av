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
                uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False, log_level="warning")
            except Exception as e:
                logger.critical("Web service thread crashed: %s", e)

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

        # Allow FastAPI server to bind to port before native window launch
        time.sleep(1.0)

        # JS-side API for our custom dark title bar (frameless window)
        class WindowAPI:
            def __init__(self):
                self._window = None
                self._maximized = False

            def minimize(self):
                try: self._window.minimize()
                except Exception: pass

            def toggle_maximize(self):
                try:
                    if self._maximized:
                        self._window.restore()
                    else:
                        self._window.maximize()
                    self._maximized = not self._maximized
                except Exception:
                    pass

            def close(self):
                try: self._window.destroy()
                except Exception: pass

        api = WindowAPI()

        logger.info("Launching standalone Aegis AV Desktop App...")
        window = webview.create_window(
            title="Aegis AV Security Suite",
            url="http://127.0.0.1:8000/",
            width=1280,
            height=820,
            min_size=(1024, 680),
            resizable=True,
            frameless=True,
            easy_drag=False,             # the HTML title bar declares the drag region
            background_color="#060912",  # avoid white flash before first paint
            js_api=api,
        )
        api._window = window
        webview.start()
        
    except Exception as e:
        logger.critical("Fatal exception in main web server thread: %s", e, exc_info=True)
        print(f"\n[FATAL ERROR] {e}\nSee logs for details.")

if __name__ == "__main__":
    main()

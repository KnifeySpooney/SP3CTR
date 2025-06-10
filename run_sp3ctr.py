# run_sp3ctr.py
# Python-based launcher for SP3CTR (specter)
# Version 0.5b - Prep for hashing

import subprocess
import time
import webbrowser
import os
import sys
import platform

# --- Configuration ---
PYTHON_EXE = sys.executable  # Uses the same Python that's running this script
BACKEND_SCRIPT_NAME = "Sp3ctrCore.py"
FRONTEND_HTML_NAME = "sp3ctr_UI.html" # Make sure this matches your HTML file
HTTP_SERVER_PORT = 8000
WEBSOCKET_PORT = 8765 # Should match Sp3ctrCore.py config

# --- Get base directory of this launcher script ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_SCRIPT_PATH = os.path.join(SCRIPT_DIR, BACKEND_SCRIPT_NAME)
FRONTEND_HTML_PATH = os.path.join(SCRIPT_DIR, FRONTEND_HTML_NAME)

# --- Functions ---

def print_header():
    """Prints a nice header for the launcher."""
    print("============================================================")
    print(" SP3CTR (specter) Python Launcher v0.5b")
    print("============================================================")
    print(f"Script Directory: {SCRIPT_DIR}")
    print(f"Python Executable: {PYTHON_EXE}")
    print("-" * 60)

def check_files():
    """Checks if the necessary script files exist."""
    print(f"\nChecking for backend script: {BACKEND_SCRIPT_PATH}...")
    if not os.path.exists(BACKEND_SCRIPT_PATH):
        print(f"ERROR: Backend script '{BACKEND_SCRIPT_NAME}' not found at '{BACKEND_SCRIPT_PATH}'.")
        print("Please ensure this launcher script is in the same directory as the SP3CTR core script.")
        return False
    print("Backend script found.")

    print(f"\nChecking for frontend HTML: {FRONTEND_HTML_PATH}...")
    if not os.path.exists(FRONTEND_HTML_PATH):
        print(f"ERROR: Frontend HTML file '{FRONTEND_HTML_NAME}' not found at '{FRONTEND_HTML_PATH}'.")
        print("Please ensure this launcher script is in the same directory as the HTML file.")
        return False
    print("Frontend HTML found.")
    return True

def start_backend_server():
    """Starts the SP3CTR backend WebSocket server in a new console window."""
    print(f"\nAttempting to start SP3CTR Backend Server ('{BACKEND_SCRIPT_NAME}')...")
    print("IMPORTANT: The backend requires administrator/root privileges for packet sniffing.")
    print("If SP3CTR fails to list interfaces or sniff, re-run this launcher script as Administrator/sudo.")

    cmd = [PYTHON_EXE, BACKEND_SCRIPT_PATH]
    
    # Platform-specific way to open a new console window
    if platform.system() == "Windows":
        process = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=SCRIPT_DIR)
    elif platform.system() == "Darwin": # macOS
        # This opens a new Terminal window and runs the command.
        # May need to adjust if default terminal is different or if user prefers integrated.
        term_cmd = f'tell app "Terminal" to do script "cd {SCRIPT_DIR} && {PYTHON_EXE} {BACKEND_SCRIPT_PATH}"'
        process = subprocess.Popen(['osascript', '-e', term_cmd])
    else: # Linux
        try:
            # Try with gnome-terminal, common on many Linux distros
            process = subprocess.Popen(['gnome-terminal', '--working-directory', SCRIPT_DIR, '--', PYTHON_EXE, BACKEND_SCRIPT_PATH])
        except FileNotFoundError:
            print("gnome-terminal not found. Starting backend in the current terminal (might be harder to manage).")
            print("You might need to install gnome-terminal or adapt this script for your preferred terminal.")
            process = subprocess.Popen(cmd, cwd=SCRIPT_DIR) # Fallback

    print(f"Backend server process started (PID: {process.pid if hasattr(process, 'pid') else 'N/A - check new window'}). A new window should have opened.")
    return process

def start_frontend_http_server():
    """Starts the Python HTTP server for the frontend in a new console window."""
    print(f"\nAttempting to start HTTP Server for Frontend (port {HTTP_SERVER_PORT})...")
    
    cmd = [PYTHON_EXE, "-m", "http.server", str(HTTP_SERVER_PORT)]

    if platform.system() == "Windows":
        process = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=SCRIPT_DIR)
    elif platform.system() == "Darwin": # macOS
        term_cmd = f'tell app "Terminal" to do script "cd {SCRIPT_DIR} && {PYTHON_EXE} -m http.server {HTTP_SERVER_PORT}"'
        process = subprocess.Popen(['osascript', '-e', term_cmd])
    else: # Linux
        try:
            process = subprocess.Popen(['gnome-terminal', '--working-directory', SCRIPT_DIR, '--', PYTHON_EXE, "-m", "http.server", str(HTTP_SERVER_PORT)])
        except FileNotFoundError:
            print("gnome-terminal not found. Starting HTTP server in the current terminal.")
            process = subprocess.Popen(cmd, cwd=SCRIPT_DIR)

    print(f"HTTP server process for frontend started (PID: {process.pid if hasattr(process, 'pid') else 'N/A - check new window'}). A new window should have opened.")
    return process

def open_browser():
    """Opens the SP3CTR frontend in the default web browser."""
    url = f"http://localhost:{HTTP_SERVER_PORT}/{FRONTEND_HTML_NAME}"
    print(f"\nWaiting a few seconds for servers to initialize...")
    time.sleep(5) # Give servers a moment
    print(f"Opening frontend in browser: {url}")
    webbrowser.open_new_tab(url)

# --- Main Execution ---
if __name__ == "__main__":
    print_header()

    if not check_files():
        input("Press Enter to exit.")
        sys.exit(1)

    backend_process = None
    frontend_server_process = None

    try:
        backend_process = start_backend_server()
        frontend_server_process = start_frontend_http_server()
        open_browser()

        print("\n============================================================")
        print(" SP3CTR Servers are running in separate windows.")
        print(" To stop SP3CTR:")
        print("   1. Close the 'SP3CTR Backend' window (or press Ctrl+C in it).")
        print("   2. Close the 'SP3CTR Frontend Server' window (or press Ctrl+C in it).")
        print("============================================================")
        print("\nThis launcher window can be closed if the servers started successfully,")
        print("or press Ctrl+C here to attempt to terminate them (experimental).")
        
        # Keep the launcher script running so Ctrl+C can be caught.
        # Or, if subprocesses are truly detached in new windows, this could exit.
        # For now, let's keep it alive to try and catch Ctrl+C for cleanup.
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nCtrl+C received. Shutting down SP3CTR servers...")
    except Exception as e:
        print(f"\nAn unexpected error occurred in the launcher: {e}")
    finally:
        if backend_process and backend_process.poll() is None: # Check if process is running
            print("Terminating backend server...")
            backend_process.terminate()
            backend_process.wait(timeout=5) # Wait a bit for it to close
        if frontend_server_process and frontend_server_process.poll() is None:
            print("Terminating frontend HTTP server...")
            frontend_server_process.terminate()
            frontend_server_process.wait(timeout=5)
        print("\nSP3CTR Launcher finished.")
        input("Press Enter to exit launcher window.")


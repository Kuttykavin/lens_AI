"""
ScreenSentry Launcher
Starts server.py and main.py silently in the background.
Only this window stays open.

Run ngrok manually in a separate terminal:
  ngrok http 5000
"""
import subprocess
import sys
import os
import time

PYTHON = sys.executable

def launch_hidden(script):
    """Launch a script with no console window."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return subprocess.Popen(
        [PYTHON, script],
        startupinfo=si,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
    )

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  🛡  ScreenSentry — Starting Services")
    print("="*50)

    print("[1/2] Starting mobile web server...")
    server_proc = launch_hidden("server.py")
    time.sleep(1)

    print("[2/2] Starting protection app...")
    main_proc = launch_hidden("main.py")

    print("\n  ✅ All services running in background.")
    print("  ℹ  This is the only window you need.")
    print("\n  📱 For mobile access, run in a separate terminal:")
    print("     ngrok http 5000")
    print("\n  Press Enter to stop all services...")
    print("="*50 + "\n")

    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        print("Stopping services...")
        try: server_proc.terminate()
        except: pass
        try: main_proc.terminate()
        except: pass
        print("Done.")

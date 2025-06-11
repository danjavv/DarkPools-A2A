import subprocess
import time
from trading_agent import order

def kill_existing_servers():
    print("Killing any existing server processes...")
    subprocess.run(['pkill', '-f', 'relay_server'])
    subprocess.run(['pkill', '-f', 'backend'])
    time.sleep(1)

def open_terminal_and_run(command, title):
    script = f'''
    tell application "Terminal"
        do script "cd {command['cwd']} && {command['cmd']}"
        set current settings of selected tab of front window to settings set "Pro"
        set custom title of selected tab of front window to "{title}"
    end tell
    '''
    subprocess.run(['osascript', '-e', script])

def main():
    kill_existing_servers()
    import os
    from pathlib import Path
    current_dir = Path(__file__).parent
    backend_dir = current_dir.parent.parent / 'backend'
    print("Starting relay server in a new terminal...")
    open_terminal_and_run({
        'cwd': str(backend_dir),
        'cmd': 'cargo run --bin relay_server'
    }, "Relay Server")
    time.sleep(2)
    print("Starting main server in a new terminal...")
    open_terminal_and_run({
        'cwd': str(backend_dir),
        'cmd': 'cargo run --bin backend'
    }, "Main Server")
    time.sleep(2)
    print("\nSubmitting orders...")
    order(False, "AAPL", 100, 150, 50)   # Buy AAPL
    time.sleep(1)
    order(True, "AAPL", 100, 150, 50)    # Sell AAPL
    time.sleep(1)
    order(False, "GOOGL", 200, 2800, 100) # Buy GOOGL
    time.sleep(1)
    order(True, "GOOGL", 200, 2800, 100)  # Sell GOOGL
    print("\nOrders submitted. Servers are running in separate terminals. Press Ctrl+C to exit this script.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()

import subprocess
import time
import socket
import json
import os
import sys
import asyncio
from pathlib import Path
from trading_agent import TradingAgent

def kill_existing_servers():
    print("Killing any existing server processes...")
    # Kill relay server
    subprocess.run(['pkill', '-f', 'relay_server'])
    # Kill main server
    subprocess.run(['pkill', '-f', 'backend'])
    # Wait a moment to ensure processes are terminated
    time.sleep(1)

def open_terminal_and_run(command, title):
    # Create an AppleScript command to open a new terminal window and run the command
    script = f'''
    tell application "Terminal"
        do script "cd {command['cwd']} && {command['cmd']}"
        set current settings of selected tab of front window to settings set "Pro"
        set custom title of selected tab of front window to "{title}"
    end tell
    '''
    subprocess.run(['osascript', '-e', script])

async def submit_orders_with_agents():
    # Create two trading agents
    agent1 = TradingAgent("Trading Agent 1", ["AAPL", "GOOGL"])
    agent2 = TradingAgent("Trading Agent 2", ["AAPL", "GOOGL"])
    
    # Define orders in sequence
    orders = [
        # Agent 1: AAPL Buy
        {
            "agent": agent1,
            "symbol": "AAPL",
            "quantity": 100,
            "price": 150,
            "side": "BUY",
            "min_execution": 50
        },
        # Agent 2: AAPL Sell
        {
            "agent": agent2,
            "symbol": "AAPL",
            "quantity": 100,
            "price": 150,
            "side": "SELL",
            "min_execution": 50
        },
        # Agent 1: GOOGL Buy
        {
            "agent": agent1,
            "symbol": "GOOGL",
            "quantity": 200,
            "price": 2800,
            "side": "BUY",
            "min_execution": 100
        },
        # Agent 2: GOOGL Sell
        {
            "agent": agent2,
            "symbol": "GOOGL",
            "quantity": 200,
            "price": 2800,
            "side": "SELL",
            "min_execution": 100
        }
    ]
    
    # Submit orders with delay between each
    for order in orders:
        print(f"\nSubmitting order through {order['agent'].name}:")
        print(f"Symbol: {order['symbol']}, Side: {order['side']}, Quantity: {order['quantity']}, Price: {order['price']}")
        await order['agent'].submit_order_with_min_exec(
            order['symbol'],
            order['quantity'],
            order['price'],
            order['side'],
            order['min_execution']
        )
        await asyncio.sleep(2)  # Wait 2 seconds between orders

async def main():
    # Kill any existing server processes first
    kill_existing_servers()
    
    # Get the absolute path to the backend directory
    current_dir = Path(__file__).parent
    backend_dir = current_dir.parent.parent / 'backend'
    
    # Start the relay server in a new terminal
    print("Starting relay server in a new terminal...")
    open_terminal_and_run({
        'cwd': str(backend_dir),
        'cmd': 'cargo run --bin relay_server'
    }, "Relay Server")
    
    # Wait a bit for the relay server to start
    time.sleep(2)
    
    # Start the main server in a new terminal
    print("Starting main server in a new terminal...")
    open_terminal_and_run({
        'cwd': str(backend_dir),
        'cmd': 'cargo run --bin backend'
    }, "Main Server")
    
    # Wait a bit for the main server to start
    time.sleep(2)
    
    # Submit orders using trading agents
    print("\nStarting order submission through trading agents...")
    await submit_orders_with_agents()
    
    print("\nServers are running in separate terminals. Press Ctrl+C to exit this script.")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    asyncio.run(main())

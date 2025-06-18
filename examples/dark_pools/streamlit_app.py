import streamlit as st
import pandas as pd
import yfinance as yf
from datetime import datetime
import subprocess
import os
import socket
import json
import time
from collections import defaultdict, deque

st.set_page_config(page_title="Dark Pools A2A Demo", layout="wide")

st.title("Dark Pools A2A Agents UI")

# Tabs for each agent
trading_tab, market_data_tab, dark_pools_tab = st.tabs([
    "Trading Agent",
    "Market Data Agent",
    "Dark Pools Agent"
])

# --- Trading Agent Tab ---
with trading_tab:
    st.header("Trading Agent: Manual Order Queue & Processing")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Servers", key="start_servers"):
            try:
                # AppleScript to open new Terminal tabs for each server
                relay_cmd = f'cd {os.path.abspath("../../backend")}; cargo run --bin relay_server'
                backend_cmd = f'cd {os.path.abspath("../../backend")}; cargo run --bin backend'
                osa_script = f'''
                tell application "Terminal"
                    do script "{relay_cmd}"
                    delay 1
                    do script "{backend_cmd}"
                end tell
                '''
                subprocess.Popen(["osascript", "-e", osa_script])
                st.success("Servers started in new Terminal windows (relay_server and backend).")
            except Exception as e:
                st.error(f"Error starting servers: {e}")
    with col2:
        if st.button("Stop Servers", key="stop_servers"):
            try:
                subprocess.run(["pkill", "-f", "relay_server"])
                subprocess.run(["pkill", "-f", "backend"])
                st.success("Servers stopped (relay_server and backend).")
            except Exception as e:
                st.error(f"Error stopping servers: {e}")

    # --- Manual Order Queue and Processing ---
    if 'orders' not in st.session_state:
        st.session_state.orders = []
    with st.form("queue_order_form"):
        o_type_q = st.selectbox("Order Type", ["Buy", "Sell"], key="queue_order_type")
        symbol_q = st.text_input("Symbol", "AAPL", key="queue_symbol")
        quantity_q = st.number_input("Quantity", min_value=1, value=100, key="queue_quantity")
        price_q = st.number_input("Price", min_value=0, value=150, key="queue_price")
        min_execution_q = st.number_input("Min Execution", min_value=1, value=50, key="queue_min_exec")
        queue_submitted = st.form_submit_button("Queue Order")
    if queue_submitted:
        o_type_bool_q = False if o_type_q == "Buy" else True
        st.session_state.orders.append((o_type_bool_q, symbol_q, int(quantity_q), int(price_q), int(min_execution_q)))
        st.success(f"Order queued: {o_type_q} {quantity_q} {symbol_q} @ {price_q} (min exec: {min_execution_q})")
    st.write(f"Queued Orders: {len(st.session_state.orders)}")
    if st.button("Start Processing Queued Orders"):
        if st.session_state.orders:
            st.info(f"Processing {len(st.session_state.orders)} orders...")
            from trading_agent import order as trading_order
            processed_symbols = []
            for o in st.session_state.orders:
                trading_order(*o)
                action = "buy" if not o[0] else "sell"
                processed_symbols.append((action, o[1]))
                time.sleep(1)  # Simulate processing delay
            # Group buys and sells by symbol
            buys = defaultdict(deque)
            sells = defaultdict(deque)
            for action, symbol in processed_symbols:
                if action == "buy":
                    buys[symbol].append(symbol)
                else:
                    sells[symbol].append(symbol)
            match_lines = []
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for symbol in set(buys.keys()).union(sells.keys()):
                while buys[symbol] and sells[symbol]:
                    match_lines.append(f"{now} buy:{symbol} sell:{symbol}")
                    buys[symbol].popleft()
                    sells[symbol].popleft()
            if match_lines:
                match_lines.append("All parties have finished.")
                with open(os.path.join(os.path.dirname(__file__), "matches_output.txt"), "a") as f:
                    for line in match_lines:
                        f.write(line + "\n")
            st.session_state.orders = []
            st.success("All queued orders processed!")
        else:
            st.warning("No orders to process.")

# --- Market Data Agent Tab ---
with market_data_tab:
    st.header("Market Data Agent: Stock Prices & Details")
    symbol_query = st.text_input("Enter symbol to fetch market data", "AAPL", key="market_data_symbol")
    if st.button("Fetch Market Data"):
        try:
            ticker = yf.Ticker(symbol_query)
            info = ticker.info
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data = {
                "price": info.get("regularMarketPrice"),
                "change": info.get("regularMarketChange"),
                "change_percent": info.get("regularMarketChangePercent"),
                "volume": info.get("regularMarketVolume"),
                "timestamp": current_time
            }
            if data["price"] is not None:
                st.write(f"**{symbol_query}** Market Data:")
                st.json(data)
            else:
                st.error(f"Could not fetch price data for {symbol_query}.")
        except Exception as e:
            st.error(f"Error fetching price for {symbol_query}: {e}")

# --- Dark Pools Agent Tab ---
with dark_pools_tab:
    st.header("Dark Pools Agent: Orders & Trading Statistics")
    st.subheader("Order Matches")
    matches_file = os.path.join(os.path.dirname(__file__), "matches_output.txt")
    if st.button("Refresh Matches"):
        st.session_state["matches_refresh"] = not st.session_state.get("matches_refresh", False)
    matches_text = ""
    if os.path.exists(matches_file):
        with open(matches_file, "r") as f:
            matches_text = f.read()
    if matches_text.strip():
        st.text(matches_text)
    else:
        st.info("No matches found.")
    # Show submitted orders (actual queued orders)
    st.subheader("Submitted Orders")
    if 'orders' in st.session_state and st.session_state.orders:
        orders_data = [
            {
                "order_type": "Buy" if not o[0] else "Sell",
                "symbol": o[1],
                "quantity": o[2],
                "price": o[3],
                "min_execution": o[4]
            }
            for o in st.session_state.orders
        ]
        st.dataframe(pd.DataFrame(orders_data))
    else:
        st.info("No submitted orders queued.")
    # Placeholder statistics
    stats = {
        "Total Orders": len(st.session_state.orders) if 'orders' in st.session_state else 0,
        "Matched Orders": 0,  # You can update this if you track matches
        "Open Orders": len(st.session_state.orders) if 'orders' in st.session_state else 0
    }
    st.subheader("Trading Statistics")
    st.json(stats) 
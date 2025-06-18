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
from dark_pools_agent import DarkPoolsAgent
from market_data_agent import MarketDataAgent
from trading_agent import TradingAgent
import asyncio
from a2a.types import Message, Role, TextPart, Part

st.set_page_config(page_title="Dark Pools A2A Demo", layout="wide")

st.title("Dark Pools A2A Agents UI")

# Tabs for each agent
trading_tab, market_data_tab, dark_pools_tab = st.tabs([
    "Trading Agent",
    "Market Data Agent",
    "Dark Pools Agent"
])

# Ensure persistent agent instances using st.session_state
if 'market_data_agent' not in st.session_state:
    st.session_state['market_data_agent'] = MarketDataAgent()
if 'dark_pools_agent' not in st.session_state:
    st.session_state['dark_pools_agent'] = DarkPoolsAgent()
if 'trading_agent' not in st.session_state:
    st.session_state['trading_agent'] = TradingAgent("TradingAgent")

market_data_agent = st.session_state['market_data_agent']
dark_pools_agent = st.session_state['dark_pools_agent']
trading_agent = st.session_state['trading_agent']

# --- Global Session Selector ---
if 'all_sessions' not in st.session_state:
    st.session_state['all_sessions'] = ['default']
if 'current_session' not in st.session_state:
    st.session_state['current_session'] = 'default'

# Session selector UI at the top
st.sidebar.header("Session Management")
session_name = st.sidebar.selectbox(
    "Select Session",
    st.session_state['all_sessions'],
    index=st.session_state['all_sessions'].index(st.session_state['current_session']) if st.session_state['current_session'] in st.session_state['all_sessions'] else 0,
    key="global_session_select"
)
st.session_state['current_session'] = session_name

# Option to create a new session
def create_new_session():
    new_session = st.sidebar.text_input("New Session Name", "", key="new_session_name")
    if st.sidebar.button("Create Session", key="create_session_btn") and new_session and new_session not in st.session_state['all_sessions']:
        st.session_state['all_sessions'].append(new_session)
        st.session_state['current_session'] = new_session
        st.experimental_rerun()
create_new_session()

# Helper to get the current session name
def get_current_session():
    return st.session_state['current_session']

def get_all_sessions_for_agent(agent_name):
    if agent_name == 'dark_pools':
        return dark_pools_agent.get_all_sessions()
    elif agent_name == 'market_data':
        return market_data_agent.get_all_sessions()
    elif agent_name == 'trading':
        return trading_agent.get_all_sessions()
    else:
        return {'default': {'state': [], 'artifacts': [], 'events': [], 'eval': []}}

# --- Trading Agent Tab ---
with trading_tab:
    st.header("Trading Agent: Manual Order Queue & Processing")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Servers", key="start_servers"):
            try:
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
                context_id = get_current_session()
                trading_agent.update_session(context_id, event="Servers started", state="servers_started")
                st.success("Servers started in new Terminal windows (relay_server and backend).")
            except Exception as e:
                st.error(f"Error starting servers: {e}")
    with col2:
        if st.button("Stop Servers", key="stop_servers"):
            try:
                subprocess.run(["pkill", "-f", "relay_server"])
                subprocess.run(["pkill", "-f", "backend"])
                context_id = get_current_session()
                trading_agent.update_session(context_id, event="Servers stopped", state="servers_stopped")
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
        context_id = get_current_session()
        trading_agent.update_session(
            context_id,
            event=f"Order queued: {o_type_q} {quantity_q} {symbol_q} @ {price_q} (min exec: {min_execution_q})",
            state="order_queued",
            artifact={
                "type": "order_queued",
                "order_type": o_type_q,
                "symbol": symbol_q,
                "quantity": int(quantity_q),
                "price": int(price_q),
                "min_execution": int(min_execution_q)
            }
        )
        st.success(f"Order queued: {o_type_q} {quantity_q} {symbol_q} @ {price_q} (min exec: {min_execution_q})")
    st.write(f"Queued Orders: {len(st.session_state.orders)}")
    if st.button("Start Processing Queued Orders"):
        if st.session_state.orders:
            st.info(f"Processing {len(st.session_state.orders)} orders...")
            from trading_agent import order as trading_order
            processed_symbols = []
            context_id = get_current_session()
            for o in st.session_state.orders:
                trading_agent.update_session(
                    context_id,
                    event=f"Order processed: {o[1]} {o[2]} @ {o[3]}",
                    state="order_processed",
                    artifact={
                        "type": "order_processed",
                        "order_type": "Buy" if not o[0] else "Sell",
                        "symbol": o[1],
                        "quantity": o[2],
                        "price": o[3],
                        "min_execution": o[4]
                    }
                )
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
                trading_agent.update_session(
                    context_id,
                    event="Order matching completed.",
                    state="order_matching_completed",
                    artifact={"type": "order_matching", "matches": match_lines}
                )
            st.session_state.orders = []
            st.success("All queued orders processed!")
        else:
            st.warning("No orders to process.")

    session_data = get_all_sessions_for_agent('trading').get(get_current_session(), {})
    st.write("**State History:**")
    st.json(session_data.get('state', []))
    st.write("**Artifacts History:**")
    st.json(session_data.get('artifacts', []))
    st.write("**Events History:**")
    st.json(session_data.get('events', []))
    st.write("**Eval History:**")
    st.json(session_data.get('eval', []))

# --- Market Data Agent Tab ---
with market_data_tab:
    st.header("Market Data Agent: Stock Prices & Details")
    symbol_query = st.text_input("Enter symbol to fetch market data", "AAPL", key="market_data_symbol")
    if st.button("Fetch Market Data"):
        # Build a message for the agent
        msg = Message(
            role=Role.user,
            messageId="streamlit-market-data",
            parts=[Part(root=TextPart(text="query_price", metadata={"symbol": symbol_query}))]
        )
        # Call the agent (handle async in Streamlit)
        result = asyncio.run(market_data_agent.handle_message(msg))
        # Optionally display the result
        if result and hasattr(result, 'parts') and result.parts:
            st.write(f"**{symbol_query}** Market Data:")
            metadata = getattr(result.parts[0].root, 'metadata', None)
            if isinstance(metadata, dict):
                st.json(metadata)
            else:
                st.error("No market data metadata returned by agent.")
        else:
            st.error(f"Could not fetch price data for {symbol_query}.")

    session_data = get_all_sessions_for_agent('market_data').get(get_current_session(), {})
    st.write("**State History:**")
    st.json(session_data.get('state', []))
    st.write("**Artifacts History:**")
    st.json(session_data.get('artifacts', []))
    st.write("**Events History:**")
    st.json(session_data.get('events', []))
    st.write("**Eval History:**")
    st.json(session_data.get('eval', []))

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

    session_data = get_all_sessions_for_agent('dark_pools').get(get_current_session(), {})
    st.write("**State History:**")
    st.json(session_data.get('state', []))
    st.write("**Artifacts History:**")
    st.json(session_data.get('artifacts', []))
    st.write("**Events History:**")
    st.json(session_data.get('events', []))
    st.write("**Eval History:**")
    st.json(session_data.get('eval', [])) 
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
import requests
import json as pyjson

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

# Helper to toggle display sections
section_keys = ['events', 'state', 'artifacts', 'eval']
for key in section_keys:
    if key not in st.session_state:
        st.session_state[key] = {'trading': False, 'market_data': False, 'dark_pools': False}

def section_button(label, agent_key, col):
    with col:
        btn = st.button(label.capitalize(), key=f"{label}_{agent_key}")
        if btn:
            st.session_state[label][agent_key] = not st.session_state[label][agent_key]
        return st.session_state[label][agent_key]

# --- Trading Agent Tab ---
with trading_tab:
    st.header("Trading Agent: Manual Order Queue & Processing")
    # Section buttons at the top, side by side
    st.write("### Sections")
    cols = st.columns(4)
    show_state = section_button('state', 'trading', cols[0])
    show_artifacts = section_button('artifacts', 'trading', cols[1])
    show_events = section_button('events', 'trading', cols[2])
    show_eval = section_button('eval', 'trading', cols[3])
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
    if show_state:
        st.write("**State History:**")
        st.json(session_data.get('state', []))
    if show_artifacts:
        st.write("**Artifacts History:**")
        st.json(session_data.get('artifacts', []))
    if show_events:
        st.write("**Events History:**")
        st.json(session_data.get('events', []))
    if show_eval:
        st.write("**Eval History:**")
        st.json(session_data.get('eval', []))

# --- Market Data Agent Tab ---
with market_data_tab:
    st.header("Market Data Agent: Stock Prices & Details")
    # Section buttons at the top, side by side
    st.write("### Sections")
    cols = st.columns(4)
    show_state = section_button('state', 'market_data', cols[0])
    show_artifacts = section_button('artifacts', 'market_data', cols[1])
    show_events = section_button('events', 'market_data', cols[2])
    show_eval = section_button('eval', 'market_data', cols[3])
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
    if show_state:
        st.write("**State History:**")
        st.json(session_data.get('state', []))
    if show_artifacts:
        st.write("**Artifacts History:**")
        st.json(session_data.get('artifacts', []))
    if show_events:
        st.write("**Events History:**")
        st.json(session_data.get('events', []))
    if show_eval:
        st.write("**Eval History:**")
        st.json(session_data.get('eval', []))

# --- Dark Pools Agent Tab ---
with dark_pools_tab:
    st.header("Dark Pools Agent: Orders & Trading Statistics")
    # Section buttons at the top, side by side
    st.write("### Sections")
    cols = st.columns(4)
    show_state = section_button('state', 'dark_pools', cols[0])
    show_artifacts = section_button('artifacts', 'dark_pools', cols[1])
    show_events = section_button('events', 'dark_pools', cols[2])
    show_eval = section_button('eval', 'dark_pools', cols[3])

    # --- Chat Interface for Trading Statistics ---
    st.subheader("Chat with Dark Pools Agent (Trading Statistics)")
    chat_key = f"chat_history_{get_current_session()}"
    if chat_key not in st.session_state:
        st.session_state[chat_key] = []
    user_query = st.text_input("Ask about anything in the trading setup (all agents, all code):", "", key="dark_pools_chat_input")
    if st.button("Send", key="dark_pools_chat_send") and user_query.strip():
        # Gather session data from all agents
        session_id = get_current_session()
        trading_data = get_all_sessions_for_agent('trading').get(session_id, {})
        market_data = get_all_sessions_for_agent('market_data').get(session_id, {})
        dark_pools_data = get_all_sessions_for_agent('dark_pools').get(session_id, {})
        # Prepare context for LLM
        context = {
            "session_id": session_id,
            "trading_agent": trading_data,
            "market_data_agent": market_data,
            "dark_pools_agent": dark_pools_data
        }
        gemini_api_key = "AIzaSyAtQb3Hi5XZN123Cmy0kqaNuWJnBvusj5g"
        gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
        prompt = (
            "You are a helpful trading assistant. "
            "You have access to the following session data from three agents: trading_agent, market_data_agent, and dark_pools_agent. "
            "Answer the user's question using this data. "
            "Session data (JSON):\n" + pyjson.dumps(context, indent=2) +
            f"\nUser question: {user_query}\n"
        )
        llm_response = None
        try:
            resp = requests.post(
                gemini_url + f"?key={gemini_api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}]
                },
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                llm_response = data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                llm_response = f"[Gemini API error {resp.status_code}] {resp.text}"
        except Exception as e:
            llm_response = f"[Gemini API error] {e}"
        response = llm_response
        if not response:
            # Fallback to previous summary logic
            def summary(data, agent_name):
                return (
                    f"{agent_name} - Artifacts: {len(data.get('artifacts', []))}, "
                    f"Events: {len(data.get('events', []))}, "
                    f"State changes: {len(data.get('state', []))}"
                )
            response = (
                f"Session statistics for all agents:\n"
                f"- {summary(trading_data, 'Trading Agent')}\n"
                f"- {summary(market_data, 'Market Data Agent')}\n"
                f"- {summary(dark_pools_data, 'Dark Pools Agent')}\n"
            )
        st.session_state[chat_key].append((user_query, response))
        # Log chat interaction in agent session
        dark_pools_agent.update_session(
            session_id,
            event=f"User asked: {user_query} | Agent replied: {response}",
            state="chat_interaction",
            artifact={"type": "chat", "user_query": user_query, "agent_response": response}
        )
    # Display chat history
    for i, (q, r) in enumerate(st.session_state[chat_key]):
        st.markdown(f"**You:** {q}")
        st.markdown(f"**Agent:** {r}")

    st.subheader("Order Matches")
    matches_file = os.path.join(os.path.dirname(__file__), "matches_output.txt")
    if st.button("Clear Matches"):
        # Clear the matches file
        open(matches_file, "w").close()
        # Clear matches in the agent interface
        if hasattr(dark_pools_agent, 'matches'):
            dark_pools_agent.matches.clear()
        # Update session state, artifacts, and events
        context_id = get_current_session()
        dark_pools_agent.update_session(
            context_id,
            event="Matches cleared.",
            state="matches_cleared",
            artifact={"type": "matches_cleared"}
        )
        st.success("Matches cleared.")
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
    if show_state:
        st.write("**State History:**")
        st.json(session_data.get('state', []))
    if show_artifacts:
        st.write("**Artifacts History:**")
        st.json(session_data.get('artifacts', []))
    if show_events:
        st.write("**Events History:**")
        st.json(session_data.get('events', []))
    if show_eval:
        st.write("**Eval History:**")
        st.json(session_data.get('eval', [])) 
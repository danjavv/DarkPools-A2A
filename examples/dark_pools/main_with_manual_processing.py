import streamlit as st
import time
from trading_agent import order

st.title("Manual Order Processing Demo")

if 'orders' not in st.session_state:
    st.session_state.orders = []

# Order submission form
with st.form("order_form"):
    o_type = st.selectbox("Order Type", ["Buy", "Sell"])
    symbol = st.text_input("Symbol", "AAPL")
    quantity = st.number_input("Quantity", min_value=1, value=100)
    price = st.number_input("Price", min_value=0, value=150)
    min_execution = st.number_input("Min Execution", min_value=1, value=50)
    submitted = st.form_submit_button("Submit Order")

if submitted:
    o_type_bool = False if o_type == "Buy" else True
    st.session_state.orders.append((o_type_bool, symbol, quantity, price, min_execution))
    st.success(f"Order queued: {o_type} {quantity} {symbol} @ {price} (min exec: {min_execution})")

st.write(f"Queued Orders: {len(st.session_state.orders)}")

if st.button("Start Processing"):
    if st.session_state.orders:
        st.info(f"Processing {len(st.session_state.orders)} orders...")
        for o in st.session_state.orders:
            order(*o)
            time.sleep(1)  # Simulate processing delay
        st.session_state.orders = []
        st.success("All orders processed!")
    else:
        st.warning("No orders to process.") 
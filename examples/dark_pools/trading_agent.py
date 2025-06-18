import socket
import json
from collections import defaultdict

def send_order(order):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Connect to the server
        server_address = ('127.0.0.1', 8080)
        print(f'Connecting to {server_address[0]}:{server_address[1]}')
        sock.connect(server_address)
        # Send data
        message = json.dumps(order).encode()
        print(f'Sending order: {order}')
        sock.sendall(message)
    finally:
        print('Closing socket')
        sock.close()

def order(o_type, symbol, quantity, price, min_execution):
    order = {
        "o_type": o_type,
        "symbol": symbol,
        "quantity": quantity,
        "price": price,
        "min_execution": min_execution
    }
    send_order(order)

class TradingAgent:
    def __init__(self, name):
        self.name = name
        # Add session tracking
        self.sessions = defaultdict(lambda: {
            'state': ['initialized'],
            'artifacts': [],
            'events': [],
            'eval': []
        })

    def update_session(self, context_id, event=None, state=None, artifact=None, eval_result=None):
        if event:
            self.sessions[context_id]['events'].append(event)
        if state:
            self.sessions[context_id]['state'].append(state)
        if artifact:
            self.sessions[context_id]['artifacts'].append(artifact)
        if eval_result:
            self.sessions[context_id]['eval'].append(eval_result)

    def get_all_sessions(self):
        return dict(self.sessions)

    def submit_order(self, o_type, symbol, quantity, price, min_execution, context_id='default'):
        self.update_session(context_id, event=f"Order submitted: {symbol} {quantity} @ {price}", state="order_submitted")
        artifact = {
            "type": "order",
            "order_type": "Buy" if not o_type else "Sell",
            "symbol": symbol,
            "quantity": quantity,
            "price": price,
            "min_execution": min_execution
        }
        self.update_session(context_id, artifact=artifact)
        # Existing order logic
        print(f"[{self.name}] Submitting order...")
        order(o_type, symbol, quantity, price, min_execution) 
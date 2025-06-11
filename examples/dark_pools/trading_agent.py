import socket
import json

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

    def submit_order(self, o_type, symbol, quantity, price, min_execution):
        print(f"[{self.name}] Submitting order...")
        order(o_type, symbol, quantity, price, min_execution) 
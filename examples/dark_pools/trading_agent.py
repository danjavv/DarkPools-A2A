from agent_base import Agent
from typing import Dict, Optional
from a2a.types import Message, Role
import random
import asyncio
from datetime import datetime
from utils import encrypt_order, decrypt_order

class TradingAgent(Agent):
    def __init__(self, name: str, symbols: list[str], initial_balance: float = 1000000.0):
        super().__init__(name)
        self.symbols = symbols
        self.balance = initial_balance
        self.positions: Dict[str, int] = {symbol: 0 for symbol in symbols}
        self.active_orders: Dict[str, Dict] = {}  # order_id -> order details

    async def handle_message(self, message: Message) -> Optional[Message]:
        if message.role == Role.agent:
            if message.content.get("type") == "order_matched_summary":
                summary = message.content["summary"]
                print(f"[{self.name}] Order matched: {summary['symbol']} {summary['quantity']} @ {summary['price']} (parties anonymized)")
                return None
            elif message.content.get("type") == "order_accepted":
                order_id = message.content["order_id"]
                if order_id in self.active_orders:
                    self.active_orders[order_id]["status"] = "active"
            elif message.content.get("type") == "order_cancelled":
                order_id = message.content["order_id"]
                if order_id in self.active_orders:
                    del self.active_orders[order_id]
        return None

    async def submit_order(self, symbol: str, quantity: int, price: float, side: str) -> None:
        """Submit a new encrypted order to the dark pool."""
        # Ensure quantity and price are multiples of 100 or 1000
        quantity = int(quantity)
        price = int(price)
        # Round quantity and price to nearest 100 (or 1000 if you prefer)
        quantity = (quantity // 100) * 100 if quantity < 1000 else (quantity // 1000) * 1000
        price = (price // 100) * 100 if price < 1000 else (price // 1000) * 1000
        min_execution = int(random.randint(1, quantity)) if quantity > 0 else 100
        order = {
            "symbol": symbol,
            "quantity": quantity,
            "price": price,
            "side": side,
            "min_execution": min_execution,
            "timestamp": int(datetime.now().timestamp())
        }
        encrypted_order = encrypt_order(order)
        order_id = f"{symbol}_{side}_{quantity}_{price}_{datetime.now().timestamp()}"
        self.active_orders[order_id] = {
            "symbol": symbol,
            "quantity": quantity,
            "price": price,
            "side": side,
            "min_execution": min_execution,
            "status": "pending"
        }
        print(f"[{self.name}] Submitting encrypted order (order_id: {order_id}) - Data is encrypted.")
        await self.send_message({
            "submit_order": {
                "encrypted_order": encrypted_order,
                "timestamp": int(order["timestamp"]),
                "order_id": order_id
            }
        })

    async def cancel_order(self, order_id: str) -> None:
        if order_id in self.active_orders:
            await self.send_message({
                "cancel_order": {
                    "order_id": order_id
                }
            })

    async def submit_order_with_min_exec(self, symbol: str, quantity: int, price: int, side: str, min_execution: int) -> None:
        """Submit a new encrypted order to the dark pool with explicit min_execution."""
        # Ensure quantity and price are multiples of 100 or 1000
        quantity = int(quantity)
        price = int(price)
        quantity = (quantity // 100) * 100 if quantity < 1000 else (quantity // 1000) * 1000
        price = (price // 100) * 100 if price < 1000 else (price // 1000) * 1000
        min_execution = int(min_execution)
        order = {
            "symbol": symbol,
            "quantity": quantity,
            "price": price,
            "side": side,
            "min_execution": min_execution,
            "timestamp": int(datetime.now().timestamp())
        }
        encrypted_order = encrypt_order(order)
        order_id = f"{symbol}_{side}_{quantity}_{price}_{datetime.now().timestamp()}"
        self.active_orders[order_id] = {
            "symbol": symbol,
            "quantity": quantity,
            "price": price,
            "side": side,
            "min_execution": min_execution,
            "status": "pending"
        }
        print(f"[{self.name}] Submitting encrypted order (order_id: {order_id}) - Data is encrypted.")
        await self.send_message({
            "submit_order": {
                "encrypted_order": encrypted_order,
                "timestamp": int(order["timestamp"]),
                "order_id": order_id
            }
        })

    async def run_trading_strategy(self):
        while True:
            symbol = random.choice(self.symbols)
            side = random.choice(["BUY", "SELL"])
            quantity = random.randint(1, 20) * 100  # Multiples of 100 up to 2000
            price = random.randint(1, 20) * 100     # Multiples of 100 up to 2000
            await self.submit_order(symbol, quantity, price, side)
            await asyncio.sleep(random.uniform(1, 5)) 
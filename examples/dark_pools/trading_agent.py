from agent_base import Agent
from typing import Dict, Optional
from a2a.types import Message, Role, AgentCard, AgentCapabilities, AgentSkill, TextPart, Part
import random
import asyncio
from datetime import datetime
from utils import encrypt_order, decrypt_order
import uuid

class TradingAgent(Agent):
    def __init__(self, name: str, symbols: list[str], initial_balance: float = 1000000.0):
        super().__init__(name)
        self.symbols = symbols
        self.balance = initial_balance
        self.positions: Dict[str, int] = {symbol: 0 for symbol in symbols}
        self.active_orders: Dict[str, Dict] = {}  # order_id -> order details

    def agent_card(self) -> AgentCard:
        return AgentCard(
            authentication=None,
            capabilities=AgentCapabilities(
                pushNotifications=False,
                stateTransitionHistory=False,
                streaming=False
            ),
            defaultInputModes=["application/json"],
            defaultOutputModes=["application/json"],
            description="A trading agent that submits encrypted buy/sell orders to the dark pool.",
            documentationUrl=None,
            name=self.name,
            provider=None,
            skills=[
                AgentSkill(
                    id="submit_order",
                    name="Submit Order",
                    description="Submit a buy or sell order for a symbol.",
                    examples=["Submit a buy order for 100 AAPL at $150."],
                    inputModes=["application/json"],
                    outputModes=["application/json"],
                    tags=["trading", "order"]
                )
            ],
            url="",
            version="1.0.0"
        )

    async def handle_message(self, message: Message) -> Optional[Message]:
        if message.role == Role.agent:
            if message.parts and hasattr(message.parts[0].root, 'text'):
                msg_type = message.parts[0].root.text
                metadata = getattr(message.parts[0].root, 'metadata', {})
            elif message.parts and hasattr(message.parts[0], 'data'):
                msg_type = None
                metadata = message.parts[0].data
            else:
                msg_type = None
                metadata = message.__dict__.get('content', {})
            if msg_type == "order_matched_summary":
                summary = metadata["summary"]
                print(f"[{self.name}] Order matched: {summary['symbol']} {summary['quantity']} @ {summary['price']} (parties anonymized)")
                return None
            elif msg_type == "order_accepted":
                order_id = metadata["order_id"]
                if order_id in self.active_orders:
                    self.active_orders[order_id]["status"] = "active"
            elif msg_type == "order_cancelled":
                order_id = metadata["order_id"]
                if order_id in self.active_orders:
                    del self.active_orders[order_id]
        return None

    async def submit_order(self, symbol: str, quantity: int, price: float, side: str) -> None:
        quantity = int(quantity)
        price = int(price)
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
        message = Message(
            role=Role.agent,
            messageId=str(uuid.uuid4()),
            parts=[Part(root=TextPart(text="submit_order", metadata={
                "encrypted_order": encrypted_order,
                "timestamp": int(order["timestamp"]),
                "order_id": order_id
            }))]
        )
        print(f"[{self.name}] Submitting encrypted order (order_id: {order_id}) - Data is encrypted.")
        await self.send_message(message)

    async def cancel_order(self, order_id: str) -> None:
        if order_id in self.active_orders:
            message = Message(
                role=Role.agent,
                messageId=str(uuid.uuid4()),
                parts=[Part(root=TextPart(text="cancel_order", metadata={"order_id": order_id}))]
            )
            await self.send_message(message)

    async def submit_order_with_min_exec(self, symbol: str, quantity: int, price: int, side: str, min_execution: int) -> None:
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
        message = Message(
            role=Role.agent,
            messageId=str(uuid.uuid4()),
            parts=[Part(root=TextPart(text="submit_order", metadata={
                "encrypted_order": encrypted_order,
                "timestamp": int(order["timestamp"]),
                "order_id": order_id
            }))]
        )
        print(f"[{self.name}] Submitting encrypted order (order_id: {order_id}) - Data is encrypted.")
        await self.send_message(message)

    async def run_trading_strategy(self):
        while True:
            symbol = random.choice(self.symbols)
            side = random.choice(["BUY", "SELL"])
            quantity = random.randint(1, 20) * 100  # Multiples of 100 up to 2000
            price = random.randint(1, 20) * 100     # Multiples of 100 up to 2000
            await self.submit_order(symbol, quantity, price, side)
            await asyncio.sleep(random.uniform(1, 5)) 
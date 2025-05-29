from agent_base import Agent
from typing import Dict, List, Optional
from dataclasses import dataclass
from a2a.types import Message, Role
import uuid
from utils import encrypt_order, decrypt_order
from collections import defaultdict, deque
import sys

@dataclass
class EncryptedOrder:
    order_id: str
    encrypted_data: str  # base64-encoded JSON
    agent_id: str
    timestamp: float

class DarkPoolsAgent(Agent):
    def __init__(self, admin_agent_id: str = "admin_agent"):
        super().__init__("dark_pools_agent")
        self.buy_queues = defaultdict(deque)   # symbol -> deque of EncryptedOrder
        self.sell_queues = defaultdict(deque)  # symbol -> deque of EncryptedOrder
        self.matches: List[Dict] = []  # List of matched orders
        self.admin_agent_id = admin_agent_id

    async def handle_message(self, message: Message) -> Optional[Message]:
        if message.role in [Role.user, Role.agent]:
            # Handle encrypted order submission
            if "submit_order" in message.content:
                enc_order_data = message.content["submit_order"]
                order_id = enc_order_data.get("order_id", str(uuid.uuid4()))
                encrypted_data = enc_order_data["encrypted_order"]
                agent_id = message.sender
                timestamp = enc_order_data.get("timestamp", 0.0)
                # Forward to MPC coordinator
                await self.send_message({
                    "type": "mpc_submit_order",
                    "encrypted_order": encrypted_data,
                    "order_id": order_id,
                    "agent_id": agent_id,
                    "timestamp": timestamp
                }, recipient="mpc_coordinator_agent")
                return Message(
                    role=Role.agent,
                    content={
                        "type": "order_accepted",
                        "order_id": order_id
                    },
                    messageId=str(uuid.uuid4()),
                    parts=[]
                )
            # Handle order cancellation (not MPC-enabled for now)
            elif "cancel_order" in message.content:
                order_id = message.content["cancel_order"]["order_id"]
                for symbol, queue in self.buy_queues.items():
                    if any(enc_order.order_id == order_id for enc_order in queue):
                        queue.remove(enc_order for enc_order in queue if enc_order.order_id == order_id)
                        print(f"[DarkPoolsAgent] Order {order_id} cancelled and remains encrypted in {symbol} queue.")
                        return Message(
                            role=Role.agent,
                            content={
                                "type": "order_cancelled",
                                "order_id": order_id
                            },
                            messageId=str(uuid.uuid4()),
                            parts=[]
                        )
                for symbol, queue in self.sell_queues.items():
                    if any(enc_order.order_id == order_id for enc_order in queue):
                        queue.remove(enc_order for enc_order in queue if enc_order.order_id == order_id)
                        print(f"[DarkPoolsAgent] Order {order_id} cancelled and remains encrypted in {symbol} queue.")
                        return Message(
                            role=Role.agent,
                            content={
                                "type": "order_cancelled",
                                "order_id": order_id
                            },
                            messageId=str(uuid.uuid4()),
                            parts=[]
                        )
        # Handle match notification from MPC coordinator
        if message.role in [Role.user, Role.agent]:
            if message.content.get("type") == "mpc_match_found":
                summary = message.content["summary"]
                buy_order_id = message.content["buy_order_id"]
                sell_order_id = message.content["sell_order_id"]
                # Notify both parties and admin
                await self.send_message({
                    "type": "order_matched_summary",
                    "summary": summary
                }, recipient=summary["parties"][0])
                await self.send_message({
                    "type": "order_matched_summary",
                    "summary": summary
                }, recipient=summary["parties"][1])
                await self.send_message({
                    "type": "admin_match_notification",
                    "summary": summary
                }, recipient=self.admin_agent_id)
                match_str = f"[MPC MATCH FOUND] {summary['symbol']} {summary['quantity']} @ {summary['price']} between {summary['parties'][0]} and {summary['parties'][1]}"
                print(match_str, flush=True)
                with open("matches_output.txt", "a") as f:
                    f.write(match_str + "\n")
                    f.flush()
        return None 
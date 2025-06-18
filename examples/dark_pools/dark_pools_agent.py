from agent_base import Agent
from typing import Dict, List, Optional
from dataclasses import dataclass
from a2a.types import Message, Role, AgentCard, AgentCapabilities, AgentSkill, TextPart, Part
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
        # Session-based tracking
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

    def get_session_data(self, context_id):
        return self.sessions[context_id]

    def agent_card(self) -> AgentCard:
        return AgentCard(
            authentication=None,
            capabilities=AgentCapabilities(
                pushNotifications=True,
                stateTransitionHistory=True,
                streaming=False
            ),
            defaultInputModes=["application/json"],
            defaultOutputModes=["application/json"],
            description="A dark pools agent that handles secure order matching and notifications.",
            documentationUrl=None,
            name=self.name,
            provider=None,
            skills=[
                AgentSkill(
                    id="match_orders",
                    name="Match Orders",
                    description="Match encrypted buy and sell orders anonymously.",
                    examples=["Match a buy and sell order for AAPL."],
                    inputModes=["application/json"],
                    outputModes=["application/json"],
                    tags=["matching", "dark pool"]
                )
            ],
            url="",
            version="1.0.0"
        )

    async def handle_message(self, message: Message) -> Optional[Message]:
        context_id = getattr(message, 'contextId', None) or getattr(message, 'metadata', {}).get('contextId', None) or 'default'
        self.update_session(context_id, event=f"Received message: {message.parts[0].root.text if message.parts else ''}")
        if message.role in [Role.user, Role.agent]:
            # Handle encrypted order submission
            if message.parts and message.parts[0].root.text == "submit_order":
                enc_order_data = message.parts[0].root.metadata
                order_id = enc_order_data.get("order_id", str(uuid.uuid4()))
                encrypted_data = enc_order_data["encrypted_order"]
                agent_id = getattr(message, 'sender', None) or self.name
                timestamp = enc_order_data.get("timestamp", 0.0)
                # Forward to MPC coordinator
                mpc_msg = Message(
                    role=Role.agent,
                    messageId=str(uuid.uuid4()),
                    parts=[Part(root=TextPart(text="mpc_submit_order", metadata={
                        "encrypted_order": encrypted_data,
                        "order_id": order_id,
                        "agent_id": agent_id,
                        "timestamp": timestamp
                    }))]
                )
                await self.send_message(mpc_msg, recipient="mpc_coordinator_agent")
                self.update_session(context_id, state="order_submitted")
                artifact = {"type": "order", "order_id": order_id, "encrypted_data": encrypted_data}
                self.update_session(context_id, artifact=artifact)
                return Message(
                    role=Role.agent,
                    messageId=str(uuid.uuid4()),
                    parts=[Part(root=TextPart(text="order_accepted", metadata={"order_id": order_id}))]
                )
            # Handle order cancellation (not MPC-enabled for now)
            elif message.parts and message.parts[0].root.text == "cancel_order":
                order_id = message.parts[0].root.metadata["order_id"]
                for symbol, queue in self.buy_queues.items():
                    for enc_order in list(queue):
                        if enc_order.order_id == order_id:
                            queue.remove(enc_order)
                            print(f"[DarkPoolsAgent] Order {order_id} cancelled and remains encrypted in {symbol} queue.")
                            self.update_session(context_id, state="order_cancelled")
                            self.update_session(context_id, event=f"Order {order_id} cancelled.")
                            return Message(
                                role=Role.agent,
                                messageId=str(uuid.uuid4()),
                                parts=[Part(root=TextPart(text="order_cancelled", metadata={"order_id": order_id}))]
                            )
                for symbol, queue in self.sell_queues.items():
                    for enc_order in list(queue):
                        if enc_order.order_id == order_id:
                            queue.remove(enc_order)
                            print(f"[DarkPoolsAgent] Order {order_id} cancelled and remains encrypted in {symbol} queue.")
                            self.update_session(context_id, state="order_cancelled")
                            self.update_session(context_id, event=f"Order {order_id} cancelled.")
                            return Message(
                                role=Role.agent,
                                messageId=str(uuid.uuid4()),
                                parts=[Part(root=TextPart(text="order_cancelled", metadata={"order_id": order_id}))]
                            )
        # Handle match notification from MPC coordinator
        if message.role in [Role.user, Role.agent]:
            if message.parts and message.parts[0].root.text == "mpc_match_found":
                summary = message.parts[0].root.metadata["summary"]
                buy_order_id = message.parts[0].root.metadata["buy_order_id"]
                sell_order_id = message.parts[0].root.metadata["sell_order_id"]
                # Notify both parties and admin
                for party in summary["parties"]:
                    notify_msg = Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="order_matched_summary", metadata={"summary": summary}))]
                    )
                    await self.send_message(notify_msg, recipient=party)
                admin_msg = Message(
                    role=Role.agent,
                    messageId=str(uuid.uuid4()),
                    parts=[Part(root=TextPart(text="admin_match_notification", metadata={"summary": summary}))]
                )
                await self.send_message(admin_msg, recipient=self.admin_agent_id)
                match_str = f"[MPC MATCH FOUND] {summary['symbol']} {summary['quantity']} @ {summary['price']} between {summary['parties'][0]} and {summary['parties'][1]}"
                print(match_str, flush=True)
                with open("matches_output.txt", "a") as f:
                    f.write(match_str + "\n")
                    f.flush()
                self.update_session(context_id, state="match_found")
                artifact = {"type": "match", "summary": summary}
                self.update_session(context_id, artifact=artifact)
                self.update_session(context_id, event=f"Match found: {summary}")
                # Optionally, add eval result (dummy example)
                self.update_session(context_id, eval_result={"score": 1.0, "details": "Match successful"})
        return None

    # New method for UI to fetch all session data
    def get_all_sessions(self):
        return dict(self.sessions)

    async def handle_message(self, message: Message) -> Optional[Message]:
        if message.role in [Role.user, Role.agent]:
            # Handle encrypted order submission
            if message.parts and message.parts[0].root.text == "submit_order":
                enc_order_data = message.parts[0].root.metadata
                order_id = enc_order_data.get("order_id", str(uuid.uuid4()))
                encrypted_data = enc_order_data["encrypted_order"]
                agent_id = getattr(message, 'sender', None) or self.name
                timestamp = enc_order_data.get("timestamp", 0.0)
                # Forward to MPC coordinator
                mpc_msg = Message(
                    role=Role.agent,
                    messageId=str(uuid.uuid4()),
                    parts=[Part(root=TextPart(text="mpc_submit_order", metadata={
                        "encrypted_order": encrypted_data,
                        "order_id": order_id,
                        "agent_id": agent_id,
                        "timestamp": timestamp
                    }))]
                )
                await self.send_message(mpc_msg, recipient="mpc_coordinator_agent")
                return Message(
                    role=Role.agent,
                    messageId=str(uuid.uuid4()),
                    parts=[Part(root=TextPart(text="order_accepted", metadata={"order_id": order_id}))]
                )
            # Handle order cancellation (not MPC-enabled for now)
            elif message.parts and message.parts[0].root.text == "cancel_order":
                order_id = message.parts[0].root.metadata["order_id"]
                for symbol, queue in self.buy_queues.items():
                    for enc_order in list(queue):
                        if enc_order.order_id == order_id:
                            queue.remove(enc_order)
                            print(f"[DarkPoolsAgent] Order {order_id} cancelled and remains encrypted in {symbol} queue.")
                            return Message(
                                role=Role.agent,
                                messageId=str(uuid.uuid4()),
                                parts=[Part(root=TextPart(text="order_cancelled", metadata={"order_id": order_id}))]
                            )
                for symbol, queue in self.sell_queues.items():
                    for enc_order in list(queue):
                        if enc_order.order_id == order_id:
                            queue.remove(enc_order)
                            print(f"[DarkPoolsAgent] Order {order_id} cancelled and remains encrypted in {symbol} queue.")
                            return Message(
                                role=Role.agent,
                                messageId=str(uuid.uuid4()),
                                parts=[Part(root=TextPart(text="order_cancelled", metadata={"order_id": order_id}))]
                            )
        # Handle match notification from MPC coordinator
        if message.role in [Role.user, Role.agent]:
            if message.parts and message.parts[0].root.text == "mpc_match_found":
                summary = message.parts[0].root.metadata["summary"]
                buy_order_id = message.parts[0].root.metadata["buy_order_id"]
                sell_order_id = message.parts[0].root.metadata["sell_order_id"]
                # Notify both parties and admin
                for party in summary["parties"]:
                    notify_msg = Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="order_matched_summary", metadata={"summary": summary}))]
                    )
                    await self.send_message(notify_msg, recipient=party)
                admin_msg = Message(
                    role=Role.agent,
                    messageId=str(uuid.uuid4()),
                    parts=[Part(root=TextPart(text="admin_match_notification", metadata={"summary": summary}))]
                )
                await self.send_message(admin_msg, recipient=self.admin_agent_id)
                match_str = f"[MPC MATCH FOUND] {summary['symbol']} {summary['quantity']} @ {summary['price']} between {summary['parties'][0]} and {summary['parties'][1]}"
                print(match_str, flush=True)
                with open("matches_output.txt", "a") as f:
                    f.write(match_str + "\n")
                    f.flush()
        return None 
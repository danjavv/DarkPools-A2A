from agent_base import Agent
from typing import Dict, List, Optional
from a2a.types import Message, Role
from utils import decrypt_order
import uuid
import sys
import os

# Add the root directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from runn import CompareGEWrapper, BinaryArithmeticShare

class MPCCoordinatorAgent(Agent):
    def __init__(self, name="mpc_coordinator_agent"):
        super().__init__(name)
        self.buy_queues: Dict[str, List[Dict]] = {}
        self.sell_queues: Dict[str, List[Dict]] = {}
        self.compare_wrapper = CompareGEWrapper()

    async def handle_message(self, message: Message) -> Optional[Message]:
        if message.role in [Role.user, Role.agent]:
            if message.content.get("type") == "mpc_submit_order":
                encrypted_order = message.content["encrypted_order"]
                order_id = message.content["order_id"]
                agent_id = message.content["agent_id"]
                timestamp = message.content["timestamp"]
                order = decrypt_order(encrypted_order)
                symbol = order["symbol"]
                side = order["side"]
                entry = {
                    "order_id": order_id,
                    "encrypted_order": encrypted_order,
                    "agent_id": agent_id,
                    "timestamp": timestamp,
                    "order": order
                }
                if side == "BUY":
                    self.buy_queues.setdefault(symbol, []).append(entry)
                else:
                    self.sell_queues.setdefault(symbol, []).append(entry)
                await self._try_match(symbol)
        return None

    async def _try_match(self, symbol: str):
        buy_q = self.buy_queues.get(symbol, [])
        sell_q = self.sell_queues.get(symbol, [])
        while buy_q and sell_q:
            buy_entry = buy_q[0]
            sell_entry = sell_q[0]
            buy_order = buy_entry["order"]
            sell_order = sell_entry["order"]
            
            # Create shares for comparison
            buy_price_share = BinaryArithmeticShare.from_int(buy_order["price"], 0)
            sell_price_share = BinaryArithmeticShare.from_int(sell_order["price"], 0)
            
            # Compare prices using compare_ge_simple
            price_comparison = self.compare_wrapper.compare_ge_simple(buy_price_share, sell_price_share)
            price_ok = price_comparison.value1 and price_comparison.value2
            
            # Calculate match quantity
            match_qty = min(buy_order["quantity"], sell_order["quantity"])
            
            # Check minimum execution requirements
            min_exec_ok = (match_qty >= buy_order["min_execution"]) and (match_qty >= sell_order["min_execution"])
            
            if price_ok and min_exec_ok:
                summary = {
                    "symbol": symbol,
                    "quantity": match_qty,
                    "price": sell_order["price"],
                    "parties": [buy_entry["agent_id"], sell_entry["agent_id"]]
                }
                # Notify DarkPoolsAgent of the match
                await self.send_message({
                    "type": "mpc_match_found",
                    "summary": summary,
                    "buy_order_id": buy_entry["order_id"],
                    "sell_order_id": sell_entry["order_id"]
                }, recipient="dark_pools_agent")
                buy_q.pop(0)
                sell_q.pop(0)
            else:
                break 
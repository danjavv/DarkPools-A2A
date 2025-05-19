from agent_base import Agent
from typing import Dict, List, Optional
from a2a.types import Message, Role
from utils import decrypt_order
import uuid
from mpyc.runtime import mpc

class MPCCoordinatorAgent(Agent):
    def __init__(self, name="mpc_coordinator_agent"):
        super().__init__(name)
        self.buy_queues: Dict[str, List[Dict]] = {}
        self.sell_queues: Dict[str, List[Dict]] = {}

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
            # Use MPyC for secure computation
            secint = mpc.SecInt()
            await mpc.start()
            s_buy_price = secint(buy_order["price"])
            s_sell_price = secint(sell_order["price"])
            s_buy_qty = secint(buy_order["quantity"])
            s_sell_qty = secint(sell_order["quantity"])
            s_buy_min_exec = secint(buy_order["min_execution"])
            s_sell_min_exec = secint(sell_order["min_execution"])
            price_ok = await mpc.output(s_buy_price >= s_sell_price)
            match_qty = await mpc.output(mpc.if_else(s_buy_qty < s_sell_qty, s_buy_qty, s_sell_qty))
            min_exec_ok = await mpc.output((match_qty >= s_buy_min_exec) & (match_qty >= s_sell_min_exec))
            await mpc.shutdown()
            if price_ok and min_exec_ok:
                summary = {
                    "symbol": symbol,
                    "quantity": int(match_qty),
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
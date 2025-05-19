import asyncio
from dark_pools_agent import DarkPoolsAgent
from market_data_agent import MarketDataAgent
from trading_agent import TradingAgent
from server import Server
from agent_base import Agent
from a2a.types import Message, Role
from mpc_coordinator_agent import MPCCoordinatorAgent

class AdminAgent(Agent):
    def __init__(self, name="admin_agent"):
        super().__init__(name)

    async def handle_message(self, message: Message):
        if message.role == Role.agent and message.content.get("type") == "admin_match_notification":
            summary = message.content["summary"]
            match_str = f"[MATCH FOUND] [ADMIN] Match: {summary['symbol']} {summary['quantity']} @ {summary['price']} between {summary['parties'][0]} and {summary['parties'][1]}"
            print(match_str, flush=True)
            with open("matches_output.txt", "a") as f:
                f.write(match_str + "\n")
        return None

async def main():
    print("[SYSTEM] Dark Pools MPC Demo starting...")
    # Create the server
    server = Server()
    
    # Create admin agent
    admin_agent = AdminAgent()
    
    # Create agents
    dark_pools_agent = DarkPoolsAgent(admin_agent_id=admin_agent.name)
    market_data_agent = MarketDataAgent()
    mpc_coordinator_agent = MPCCoordinatorAgent()
    
    # Create trading agents with different symbols
    trading_agent1 = TradingAgent("trader1", ["AAPL", "GOOGL", "MSFT"])
    trading_agent2 = TradingAgent("trader2", ["AAPL", "GOOGL", "MSFT"])
    
    # Register agents with the server and set _server
    for agent in [admin_agent, dark_pools_agent, market_data_agent, mpc_coordinator_agent, trading_agent1, trading_agent2]:
        agent._server = server
        server.register_agent(agent)
    
    # Start the server
    await server.start()

    # Submit only two forced orders: one buy and one sell for AAPL
    print("[SYSTEM] Submitting a matching BUY and SELL order for AAPL...")
    symbol = "AAPL"
    quantity = 1000
    price = 1000
    min_execution = 1000
    await trading_agent1.submit_order_with_min_exec(symbol, quantity, price, "BUY", min_execution)
    await trading_agent2.submit_order_with_min_exec(symbol, quantity, price, "SELL", min_execution)
    print("[SYSTEM] Forced orders submitted.")

    # Print the order book for verification
    print("[SYSTEM] (MPC) Printing order book after forced orders:")
    # For demo, print the MPC coordinator's queues
    for symbol in set(list(mpc_coordinator_agent.buy_queues.keys()) + list(mpc_coordinator_agent.sell_queues.keys())):
        print(f"  Symbol: {symbol}")
        print(f"    BUY queue:")
        for entry in mpc_coordinator_agent.buy_queues[symbol]:
            order = entry['order']
            print(f"      OrderID: {entry['order_id']}, Agent: {entry['agent_id']}, Qty: {order['quantity']}, Price: {order['price']}, MinExec: {order['min_execution']}")
        print(f"    SELL queue:")
        for entry in mpc_coordinator_agent.sell_queues[symbol]:
            order = entry['order']
            print(f"      OrderID: {entry['order_id']}, Agent: {entry['agent_id']}, Qty: {order['quantity']}, Price: {order['price']}, MinExec: {order['min_execution']}")
    total_orders = sum(len(q) for q in mpc_coordinator_agent.buy_queues.values()) + sum(len(q) for q in mpc_coordinator_agent.sell_queues.values())
    print(f"[SYSTEM] (MPC) Total orders in all queues after forced orders: {total_orders}")

    # Wait longer to allow matching logic to run
    await asyncio.sleep(15)

    # Directly check the buy and sell queues for AAPL and print/write a match if both have an order
    # For MPC, check the coordinator's queues
    symbol = "AAPL"
    buy_q = mpc_coordinator_agent.buy_queues.get(symbol, [])
    sell_q = mpc_coordinator_agent.sell_queues.get(symbol, [])
    if buy_q and sell_q:
        buy_entry = buy_q[0]
        sell_entry = sell_q[0]
        buy_order = buy_entry["order"]
        sell_order = sell_entry["order"]
        match_qty = min(buy_order["quantity"], sell_order["quantity"])
        if buy_order["price"] >= sell_order["price"] and match_qty >= buy_order["min_execution"] and match_qty >= sell_order["min_execution"]:
            match_str = f"[SYNC MATCH FOUND] {symbol} {match_qty} @ {sell_order['price']} between {buy_entry['agent_id']} and {sell_entry['agent_id']}"
            print(match_str, flush=True)
            with open("matches_output.txt", "a") as f:
                f.write(match_str + "\n")
        else:
            print("[SYNC CHECK] No compatible match found in queues.")
    else:
        print("[SYNC CHECK] One or both queues are empty after sleep.")

    # Print the contents of matches_output.txt
    print("[SYSTEM] Contents of matches_output.txt:")
    try:
        with open("matches_output.txt", "r") as f:
            print(f.read())
    except FileNotFoundError:
        print("[SYSTEM] matches_output.txt not found.")

    # Stop the server
    await server.stop()

if __name__ == "__main__":
    asyncio.run(main()) 
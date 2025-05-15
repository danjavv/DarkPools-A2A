# Dark Pools Demo

_Note: This demo provides a minimal `Agent` base class in `agent_base.py` for agent logic simulation._

This demo showcases a dark pools trading system using the A2A Python SDK. The system consists of multiple agents:

1. Dark Pools Agent - Handles order matching securely
2. Market Data Agent - Provides real-time market information
3. Trading Agents - Submit buy/sell orders to the dark pool

## Features

- Secure order matching in dark pools
- Real-time market data using yfinance
- Multiple trading agents with different strategies
- Position and balance tracking for each trading agent

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the demo:
```bash
python main.py
```

## How it Works

1. The Dark Pools Agent receives orders from trading agents and matches them based on price and quantity
2. The Market Data Agent provides real-time price information for stocks
3. Trading Agents submit random buy/sell orders and maintain their positions and balances
4. When orders are matched, the Dark Pools Agent notifies the relevant trading agents
5. Trading agents update their positions and balances based on matched orders

## Demo Duration

The demo runs for 5 minutes by default. You can modify the duration in `main.py` by changing the `asyncio.sleep(300)` value.

## Stopping the Demo

Press Ctrl+C to stop the demo gracefully. The system will:
1. Cancel all trading tasks
2. Stop the server
3. Clean up resources 
# Dark Pools Demo

_Note: This demo provides a minimal `Agent` base class in `agent_base.py` for agent logic simulation._

This demo showcases a dark pools trading system using the A2A Python SDK. The system consists of multiple agents:

1. Dark Pools Agent - Handles order matching securely
2. Market Data Agent - Provides real-time market information
3. Trading Agents - Submit buy/sell orders to the dark pool

## Google Docs 

1. https://docs.google.com/document/d/12UkfykkRZauD-IjDgWmcboLXSk3wzIrNPbmSfp0kRwA/edit?usp=sharing
2. https://docs.google.com/document/d/1QcgBR1hDCae-TbnBORLisdACFGeNcgModAH_mN37ZEk/edit?usp=sharing

## Video Demos

1. https://www.loom.com/share/aeb9aa3cb1724efebf7af62dd28f17bf?sid=1b08a54a-591a-4bda-a9a1-194ca09ee398
2. https://www.loom.com/share/7ce8b4bf549f4798bc9b9f982a0ba675?sid=5dff50c3-1609-4a29-a8fa-caf4b07b98ad

## Features

- Secure order matching in dark pools
- Real-time market data using yfinance
- Multiple trading agents with different strategies
- Position and balance tracking for each trading agent

## Setup

See the Quickstart section below for the recommended way to set up and run the demo after cloning the repository.

## Quickstart: Running the Demo After Cloning

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd DarkPools-A2A/examples/dark_pools
   ```

2. **(Recommended) Create and activate a Python 3.9 environment:**
   ```bash
   conda create -n darkpools-demo python=3.9
   conda activate darkpools-demo
   ```
   Or with `venv`:
   ```bash
   python3.9 -m venv venv
   source venv/bin/activate
   ```

3. **Install required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install the main package in development mode (from the repo root):**
   ```bash
   cd ../../..
   pip install -e .
   cd examples/dark_pools
   ```

5. **Run the demo:**
   ```bash
   python main.py
   ```

## How it Works

![flow_diagram](https://github.com/user-attachments/assets/13272904-ddcf-434f-b6ab-91d13ffe47fe)

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

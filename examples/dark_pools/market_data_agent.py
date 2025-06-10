from agent_base import Agent
from typing import Dict, Optional
from a2a.types import Message, Role, AgentCard, AgentCapabilities, AgentSkill, TextPart
import yfinance as yf
from datetime import datetime
import uuid

class MarketDataAgent(Agent):
    def __init__(self):
        super().__init__("market_data_agent")
        self.cache: Dict[str, Dict] = {}  # symbol -> price data
        self.cache_timeout = 60  # seconds

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
            description="A market data agent that provides real-time price information for stocks.",
            documentationUrl=None,
            name=self.name,
            provider=None,
            skills=[
                AgentSkill(
                    id="query_price",
                    name="Query Price",
                    description="Get the current price for a symbol.",
                    examples=["Query the price for AAPL."],
                    inputModes=["application/json"],
                    outputModes=["application/json"],
                    tags=["market data", "price"]
                )
            ],
            url="",
            version="1.0.0"
        )

    async def handle_message(self, message: Message) -> Optional[Message]:
        if message.role == Role.user:
            if message.parts and message.parts[0].root.text == "query_price":
                symbol = message.parts[0].root.metadata["symbol"]
                price_data = await self._get_price(symbol)
                if price_data:
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[TextPart(text="price_data", metadata={"symbol": symbol, "data": price_data})]
                    )
                else:
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[TextPart(text="error", metadata={"message": f"Could not fetch price data for {symbol}"})]
                    )
        return None

    async def _get_price(self, symbol: str) -> Optional[Dict]:
        """Get the current price for a symbol."""
        current_time = datetime.now().timestamp()
        
        # Check cache
        if symbol in self.cache:
            cache_data = self.cache[symbol]
            if current_time - cache_data["timestamp"] < self.cache_timeout:
                return cache_data["data"]
        
        try:
            # Fetch real-time data using yfinance
            ticker = yf.Ticker(symbol)
            info = ticker.info
            
            price_data = {
                "price": info.get("regularMarketPrice"),
                "change": info.get("regularMarketChange"),
                "change_percent": info.get("regularMarketChangePercent"),
                "volume": info.get("regularMarketVolume"),
                "timestamp": current_time
            }
            
            # Update cache
            self.cache[symbol] = {
                "data": price_data,
                "timestamp": current_time
            }
            
            return price_data
        except Exception as e:
            print(f"Error fetching price for {symbol}: {e}")
            return None 
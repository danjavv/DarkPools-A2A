from agent_base import Agent
from typing import Dict, Optional
from a2a.types import Message, Role
import yfinance as yf
from datetime import datetime

class MarketDataAgent(Agent):
    def __init__(self):
        super().__init__("market_data_agent")
        self.cache: Dict[str, Dict] = {}  # symbol -> price data
        self.cache_timeout = 60  # seconds

    async def handle_message(self, message: Message) -> Optional[Message]:
        if message.role == Role.user:
            if "query_price" in message.content:
                symbol = message.content["query_price"]["symbol"]
                price_data = await self._get_price(symbol)
                
                if price_data:
                    return Message(
                        role=Role.agent,
                        content={
                            "type": "price_data",
                            "symbol": symbol,
                            "data": price_data
                        }
                    )
                else:
                    return Message(
                        role=Role.agent,
                        content={
                            "type": "error",
                            "message": f"Could not fetch price data for {symbol}"
                        }
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
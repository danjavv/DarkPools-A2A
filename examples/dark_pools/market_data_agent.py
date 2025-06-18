from agent_base import Agent
from typing import Dict, Optional
from a2a.types import Message, Role, AgentCard, AgentCapabilities, AgentSkill, TextPart, Part
import yfinance as yf
from datetime import datetime
import uuid
from collections import defaultdict

class MarketDataAgent(Agent):
    def __init__(self):
        super().__init__("market_data_agent")
        self.cache: Dict[str, Dict] = {}  # symbol -> price data
        self.cache_timeout = 60  # seconds
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
        context_id = getattr(message, 'contextId', None)
        if context_id is None:
            metadata = getattr(message, 'metadata', None)
            if isinstance(metadata, dict):
                context_id = metadata.get('contextId', None)
        if context_id is None:
            context_id = 'default'
        self.update_session(context_id, event=f"Received message: {message.parts[0].root.text if message.parts else ''}")
        if message.role == Role.user:
            if message.parts and message.parts[0].root.text == "query_price":
                metadata = getattr(message.parts[0].root, 'metadata', None)
                if not isinstance(metadata, dict) or "symbol" not in metadata:
                    self.update_session(context_id, state="error")
                    self.update_session(context_id, event="No symbol provided in metadata.")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="error", metadata={"message": "No symbol provided in metadata."}))]
                    )
                symbol = metadata["symbol"]
                price_data = await self._get_price(symbol)
                if price_data:
                    self.update_session(context_id, state="price_queried")
                    artifact = {"type": "price_data", "symbol": symbol, "data": price_data}
                    self.update_session(context_id, artifact=artifact)
                    self.update_session(context_id, event=f"Price data for {symbol}: {price_data}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="price_data", metadata={"symbol": symbol, "data": price_data}))]
                    )
                else:
                    self.update_session(context_id, state="error")
                    self.update_session(context_id, event=f"Error fetching price for {symbol}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="error", metadata={"message": f"Could not fetch price data for {symbol}"}))]
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

    # New method for UI to fetch all session data
    def get_all_sessions(self):
        return dict(self.sessions) 
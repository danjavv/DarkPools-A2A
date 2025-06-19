from agent_base import Agent
from typing import Dict, Optional, List
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
                stateTransitionHistory=True,
                streaming=False
            ),
            defaultInputModes=["application/json"],
            defaultOutputModes=["application/json"],
            description="A market data agent that provides real-time price information, market analysis, and trading insights for stocks.",
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
                ),
                AgentSkill(
                    id="market_analysis",
                    name="Market Analysis",
                    description="Provide market analysis and insights for stocks.",
                    examples=["Analyze the market trends for tech stocks."],
                    inputModes=["application/json"],
                    outputModes=["application/json"],
                    tags=["market data", "analysis"]
                ),
                AgentSkill(
                    id="trading_insights",
                    name="Trading Insights",
                    description="Provide trading insights and recommendations.",
                    examples=["What are the best stocks to watch today?"],
                    inputModes=["application/json"],
                    outputModes=["application/json"],
                    tags=["market data", "trading"]
                ),
                AgentSkill(
                    id="stock_info",
                    name="Stock Information",
                    description="Get detailed information about a stock.",
                    examples=["Get information about AAPL stock."],
                    inputModes=["application/json"],
                    outputModes=["application/json"],
                    tags=["market data", "stock info"]
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
            
            elif message.parts and message.parts[0].root.text == "market_analysis":
                metadata = getattr(message.parts[0].root, 'metadata', None)
                symbol = metadata.get("symbol", "general") if isinstance(metadata, dict) else "general"
                analysis_data = await self._get_market_analysis(symbol)
                if analysis_data:
                    self.update_session(context_id, state="analysis_provided")
                    artifact = {"type": "market_analysis", "symbol": symbol, "data": analysis_data}
                    self.update_session(context_id, artifact=artifact)
                    self.update_session(context_id, event=f"Market analysis for {symbol}: {analysis_data}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="market_analysis", metadata={"symbol": symbol, "data": analysis_data}))]
                    )
                else:
                    self.update_session(context_id, state="error")
                    self.update_session(context_id, event=f"Error providing market analysis for {symbol}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="error", metadata={"message": f"Could not provide market analysis for {symbol}"}))]
                    )
            
            elif message.parts and message.parts[0].root.text == "trading_insights":
                metadata = getattr(message.parts[0].root, 'metadata', None)
                insight_type = metadata.get("type", "general") if isinstance(metadata, dict) else "general"
                insights_data = await self._get_trading_insights(insight_type)
                if insights_data:
                    self.update_session(context_id, state="insights_provided")
                    artifact = {"type": "trading_insights", "insight_type": insight_type, "data": insights_data}
                    self.update_session(context_id, artifact=artifact)
                    self.update_session(context_id, event=f"Trading insights for {insight_type}: {insights_data}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="trading_insights", metadata={"insight_type": insight_type, "data": insights_data}))]
                    )
                else:
                    self.update_session(context_id, state="error")
                    self.update_session(context_id, event=f"Error providing trading insights for {insight_type}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="error", metadata={"message": f"Could not provide trading insights for {insight_type}"}))]
                    )
            
            elif message.parts and message.parts[0].root.text == "stock_info":
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
                stock_info = await self._get_stock_info(symbol)
                if stock_info:
                    self.update_session(context_id, state="stock_info_provided")
                    artifact = {"type": "stock_info", "symbol": symbol, "data": stock_info}
                    self.update_session(context_id, artifact=artifact)
                    self.update_session(context_id, event=f"Stock info for {symbol}: {stock_info}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="stock_info", metadata={"symbol": symbol, "data": stock_info}))]
                    )
                else:
                    self.update_session(context_id, state="error")
                    self.update_session(context_id, event=f"Error fetching stock info for {symbol}")
                    return Message(
                        role=Role.agent,
                        messageId=str(uuid.uuid4()),
                        parts=[Part(root=TextPart(text="error", metadata={"message": f"Could not fetch stock info for {symbol}"}))]
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

    async def _get_market_analysis(self, symbol: str) -> Optional[Dict]:
        """Get market analysis for a symbol."""
        try:
            ticker = yf.Ticker(symbol)
            info = ticker.info
            
            # Get historical data for analysis
            hist = ticker.history(period="1mo")
            
            analysis_data = {
                "symbol": symbol,
                "company_name": info.get("longName", "Unknown"),
                "sector": info.get("sector", "Unknown"),
                "industry": info.get("industry", "Unknown"),
                "market_cap": info.get("marketCap"),
                "pe_ratio": info.get("trailingPE"),
                "price_to_book": info.get("priceToBook"),
                "dividend_yield": info.get("dividendYield"),
                "beta": info.get("beta"),
                "fifty_day_average": info.get("fiftyDayAverage"),
                "two_hundred_day_average": info.get("twoHundredDayAverage"),
                "volume_average": info.get("averageVolume"),
                "price_range": {
                    "high_52_week": info.get("fiftyTwoWeekHigh"),
                    "low_52_week": info.get("fiftyTwoWeekLow")
                },
                "recent_performance": {
                    "one_month_change": hist['Close'].pct_change().iloc[-1] if len(hist) > 1 else None,
                    "volatility": hist['Close'].pct_change().std() if len(hist) > 1 else None
                }
            }
            
            return analysis_data
        except Exception as e:
            print(f"Error fetching market analysis for {symbol}: {e}")
            return None

    async def _get_trading_insights(self, insight_type: str) -> Optional[Dict]:
        """Get trading insights based on type."""
        try:
            # Popular tech stocks for insights
            tech_stocks = ["AAPL", "MSFT", "GOOGL", "AMZN", "TSLA", "META", "NVDA", "NFLX"]
            
            if insight_type == "tech":
                symbols = tech_stocks
            elif insight_type == "general":
                symbols = ["AAPL", "MSFT", "GOOGL", "AMZN", "TSLA"]
            else:
                symbols = [insight_type.upper()]
            
            insights = []
            for symbol in symbols:
                try:
                    ticker = yf.Ticker(symbol)
                    info = ticker.info
                    
                    insight = {
                        "symbol": symbol,
                        "current_price": info.get("regularMarketPrice"),
                        "change_percent": info.get("regularMarketChangePercent"),
                        "volume": info.get("regularMarketVolume"),
                        "market_cap": info.get("marketCap"),
                        "pe_ratio": info.get("trailingPE"),
                        "recommendation": self._get_recommendation(info)
                    }
                    insights.append(insight)
                except Exception as e:
                    print(f"Error fetching insight for {symbol}: {e}")
                    continue
            
            insights_data = {
                "type": insight_type,
                "timestamp": datetime.now().timestamp(),
                "insights": insights,
                "summary": self._generate_insights_summary(insights)
            }
            
            return insights_data
        except Exception as e:
            print(f"Error generating trading insights: {e}")
            return None

    async def _get_stock_info(self, symbol: str) -> Optional[Dict]:
        """Get detailed stock information."""
        try:
            ticker = yf.Ticker(symbol)
            info = ticker.info
            
            # Get financial data
            financials = ticker.financials
            balance_sheet = ticker.balance_sheet
            
            stock_info = {
                "symbol": symbol,
                "company_name": info.get("longName", "Unknown"),
                "short_name": info.get("shortName", "Unknown"),
                "sector": info.get("sector", "Unknown"),
                "industry": info.get("industry", "Unknown"),
                "country": info.get("country", "Unknown"),
                "website": info.get("website", "Unknown"),
                "business_summary": info.get("longBusinessSummary", "No summary available"),
                "market_data": {
                    "current_price": info.get("regularMarketPrice"),
                    "previous_close": info.get("regularMarketPreviousClose"),
                    "open": info.get("regularMarketOpen"),
                    "day_high": info.get("dayHigh"),
                    "day_low": info.get("dayLow"),
                    "volume": info.get("regularMarketVolume"),
                    "market_cap": info.get("marketCap"),
                    "enterprise_value": info.get("enterpriseValue")
                },
                "valuation": {
                    "pe_ratio": info.get("trailingPE"),
                    "forward_pe": info.get("forwardPE"),
                    "price_to_book": info.get("priceToBook"),
                    "price_to_sales": info.get("priceToSalesTrailing12Months"),
                    "enterprise_to_revenue": info.get("enterpriseToRevenue"),
                    "enterprise_to_ebitda": info.get("enterpriseToEbitda")
                },
                "dividend_info": {
                    "dividend_rate": info.get("dividendRate"),
                    "dividend_yield": info.get("dividendYield"),
                    "payout_ratio": info.get("payoutRatio"),
                    "five_year_avg_dividend_yield": info.get("fiveYearAvgDividendYield")
                },
                "growth_metrics": {
                    "revenue_growth": info.get("revenueGrowth"),
                    "earnings_growth": info.get("earningsGrowth"),
                    "revenue_per_share": info.get("revenuePerShare"),
                    "return_on_equity": info.get("returnOnEquity"),
                    "return_on_assets": info.get("returnOnAssets")
                },
                "technical_indicators": {
                    "beta": info.get("beta"),
                    "fifty_day_average": info.get("fiftyDayAverage"),
                    "two_hundred_day_average": info.get("twoHundredDayAverage"),
                    "fifty_two_week_high": info.get("fiftyTwoWeekHigh"),
                    "fifty_two_week_low": info.get("fiftyTwoWeekLow")
                }
            }
            
            return stock_info
        except Exception as e:
            print(f"Error fetching stock info for {symbol}: {e}")
            return None

    def _get_recommendation(self, info: Dict) -> str:
        """Generate a simple recommendation based on stock data."""
        try:
            pe_ratio = info.get("trailingPE")
            change_percent = info.get("regularMarketChangePercent", 0)
            
            if pe_ratio is None:
                return "Insufficient data"
            
            if pe_ratio < 15 and change_percent > 0:
                return "Strong Buy"
            elif pe_ratio < 20 and change_percent > 0:
                return "Buy"
            elif pe_ratio > 30 or change_percent < -5:
                return "Hold"
            else:
                return "Watch"
        except:
            return "Insufficient data"

    def _generate_insights_summary(self, insights: List[Dict]) -> str:
        """Generate a summary of trading insights."""
        if not insights:
            return "No insights available"
        
        total_insights = len(insights)
        positive_changes = sum(1 for i in insights if i.get("change_percent", 0) > 0)
        negative_changes = sum(1 for i in insights if i.get("change_percent", 0) < 0)
        
        summary = f"Analysis of {total_insights} stocks:\n"
        summary += f"- Positive performers: {positive_changes}\n"
        summary += f"- Negative performers: {negative_changes}\n"
        summary += f"- Neutral: {total_insights - positive_changes - negative_changes}\n"
        
        if insights:
            avg_change = sum(i.get("change_percent", 0) for i in insights) / total_insights
            summary += f"- Average change: {avg_change:.2f}%\n"
        
        return summary

    # New method for UI to fetch all session data
    def get_all_sessions(self):
        return dict(self.sessions) 
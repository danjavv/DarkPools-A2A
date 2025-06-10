from typing import Optional, Any
from a2a.types import Role, Message, AgentCard
from abc import ABC, abstractmethod

class Agent(ABC):
    def __init__(self, name: str):
        self.name = name
        self._server = None  # Will be set by the server
        self.role = Role.agent

    @abstractmethod
    def agent_card(self) -> AgentCard:
        """Return the AgentCard metadata for this agent."""
        pass

    async def handle_message(self, message: Message) -> Optional[Message]:
        raise NotImplementedError("handle_message must be implemented by subclasses")

    async def send_message(self, message: Message, recipient: Optional[str] = None):
        if self._server is not None:
            await self._server.route_message(self, message, recipient)
        else:
            raise RuntimeError("Agent is not registered with a server.") 
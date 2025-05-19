from typing import Optional, Any
from a2a.types import Role

class Agent:
    def __init__(self, name: str):
        self.name = name
        self._server = None  # Will be set by the server
        self.role = Role.agent

    async def handle_message(self, message: Any) -> Optional[Any]:
        raise NotImplementedError("handle_message must be implemented by subclasses")

    async def send_message(self, content: Any, recipient: Optional[str] = None):
        if self._server is not None:
            await self._server.route_message(self, content, recipient)
        else:
            raise RuntimeError("Agent is not registered with a server.") 
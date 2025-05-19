from typing import Dict, Optional, Any

class Server:
    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.running = False

    def register_agent(self, agent: Any):
        self.agents[agent.name] = agent
        agent._server = self

    async def route_message(self, sender: Any, content: Any, recipient: Optional[str] = None):
        if recipient:
            agent = self.agents.get(recipient)
            if agent:
                await agent.handle_message(
                    type('Message', (), {'role': sender.role, 'content': content, 'sender': sender.name})
                )
        else:
            # Broadcast to all except sender
            for name, agent in self.agents.items():
                if name != sender.name:
                    await agent.handle_message(
                        type('Message', (), {'role': sender.role, 'content': content, 'sender': sender.name})
                    )

    async def start(self):
        self.running = True

    async def stop(self):
        self.running = False 
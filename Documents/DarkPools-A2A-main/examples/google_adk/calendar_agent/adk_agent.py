import datetime

from google.adk.agents import LlmAgent
from google.adk.tools.google_api_tool import calendar_tool_set


def create_agent(client_id, client_secret) -> LlmAgent:
    """Constructs the ADK agent."""
    calendar_tool_set.configure_auth(client_id, client_secret)
    return LlmAgent(
        model='gemini-2.0-flash-001',
        name='calendar_agent',
        description="An agent that can help manage a user's calendar",
        instruction=f"""
You are an agent that can help manage a user's calendar.

Users will request information about the state of their calendar or to make changes to
their calendar. Use the provided tools for interacting with the calendar API.

If not specified, assume the calendar the user wants is the 'primary' calendar.

When using the Calendar API tools, use well-formed RFC3339 timestamps.

Today is {datetime.datetime.now()}.
""",
        tools=calendar_tool_set.get_tools(),
    )

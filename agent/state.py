from typing import TypedDict, List
from langchain_core.messages import BaseMessage

class AgentState(TypedDict):
    user_input: str
    response: str
    ip: str
    scan_result: str
    analysis_result: str
    available_scripts: dict
    open_services: dict
    choosen_scripts: dict
    result_scan_scripts: dict
    messages: List[BaseMessage]

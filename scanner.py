from typing import TypedDict, List

import json

from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, MessagesState, START, END
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from scannertools import NmapTools

from mermaid import MermaidGraphGenerator

class AgentState(TypedDict):
    """ 
    I give that to the Agent to know data types
    """
    user_input: str
    response: str
    ip: str
    messages: List[BaseMessage]

class LLMAgent:
    """
    Agent that is going to use the LLM and use tools
    """

    def __init__(self, model_name="llama3.1", base_url="http://localhost:11434"):
        """ 
        Init agent
        """
        self.llm = ChatOllama(model=model_name, base_url=base_url)
        self.tool_node = NmapTools.get_tool_node()
        self.graph = self.build_graph()

        # Generate graph (I use Mermaid)
        self.graph_visualizer = MermaidGraphGenerator(self.graph)
        self.graph_visualizer.generate_html()

        

    def build_graph(self):
        """
        Constructs the LangGraph state graph that orchestrates the agent's behavior.
        """
        graph = StateGraph(AgentState)  

        graph.add_node("get_ip", self.get_ip)
        graph.add_node("get_scan_type", self.get_scan_type)
        graph.add_node("get_full_scan", self.get_full_scan)
        graph.add_node("get_default_scan", self.get_default_scan)
        graph.add_node("get_os_scan", self.get_os_scan)

        graph.add_edge(START, "get_ip")  
        graph.add_edge("get_ip", "get_scan_type")
        
        graph.add_conditional_edges(
            "get_scan_type",
            self.route_scan,
            {
                "full_scan": "get_full_scan",
                "os_detection_scan": "get_os_scan",
                "default_scan": "get_default_scan"
            }
        )

        return graph.compile()


    def route_scan(self, state: AgentState) -> str:
        """
        Determines the next step based on the scan type detected.
        """
        scan_type = state["response"]  
        print(f"[+] - Routing to scan type: {scan_type}")

        if scan_type == "full_scan":
            return "full_scan"
        elif scan_type == "os_detection_scan":
            return "os_detection_scan"
        else:
            return "default_scan"


    def get_ip(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        extracted_ip = NmapTools.grep_ip.invoke(user_input)

        print(f"[+] - Extracted IP: {extracted_ip}")

        state["ip"] = extracted_ip

        return state

    def get_scan_type(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        scan_type = NmapTools.get_scan_type.invoke(user_input)

        tool_call_message = AIMessage(
            content="",
            tool_calls=[{
                "name": "get_scan_type",
                "args": {"user_input": user_input},
                "id": "tool_call_2",
                "type": "tool_call",
            }]
        )

        print(f"[+] - Scan Type Detected: {scan_type}")

        state["messages"].append(tool_call_message)
        state["response"] = scan_type 
        return state


    def get_full_scan(self, state: AgentState) -> AgentState:
        """
        Get the full scan
        """
        ip = state.get("ip", "Unknown")
        print(f"[+] - Running full scan detection scan on {ip}...")

        return state

    def get_default_scan(self, state: AgentState) -> AgentState:
        """
        Get the default scan
        """
        ip = state.get("ip", "Unknown")
        print(f"[+] - Running default scan on {ip}...")

        result_scan = NmapTools.default_scan.invoke(ip)
        tool_call_message = AIMessage(
            content="",
            tool_calls=[{
                "name": "get_default_scan",
                "args": {"ip": ip},
                "id": "tool_call_3",
                "type": "tool_call",
            }]
        )

        print(f"[+] - Scan result: {result_scan}")

        return state

    def get_os_scan(self, state: AgentState) -> AgentState:
        """
        Get the os scan
        """
        ip = state.get("ip", "Unknown")
        print(f"[+] - Running OS detection scan on {ip}...")

        return state

    def get_response(self, state: AgentState) -> AgentState:
        """
        Get the response from the LLM based on the state.
        """
        messages = state["messages"]

        response = self.llm.invoke(messages)
        ai_response = AIMessage(content=response.content)

        state["messages"].append(ai_response)
        state["response"] = ai_response

        return state

    def ask(self, user_input):
        print(f">> - User: {user_input}")

        initial_state = {
            "user_input": user_input,
            "response": "",
            "messages": []
        }

        final_state = self.graph.invoke(initial_state)




agent = LLMAgent()

agent.ask("Can you scan the IP 192.168.1.26")

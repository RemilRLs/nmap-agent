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
        graph.add_edge(START, "get_ip")  

        return graph.compile() 



    def get_ip(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        extracted_ip = NmapTools.grep_ip.invoke(user_input)

        print(f"[+] - Extracted IP: {extracted_ip}")



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

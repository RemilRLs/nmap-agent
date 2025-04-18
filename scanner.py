from typing import TypedDict, List

import json
import os
import xmltodict

from langchain_openai import ChatOpenAI

from langgraph.graph import StateGraph, MessagesState, START, END
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from tools.nmap_tools import NmapTools

from utils.mermaid_graph import MermaidGraphGenerator

class AgentState(TypedDict):
    """ 
    I give that to the Agent to know data types
    """
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

class LLMAgent:
    """
    Agent that is going to use the LLM and use tools
    """

    def __init__(self, model_name="llama3.1", base_url="http://localhost:11434"):
        """ 
        Init agent
        """
        self.llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0,
            openai_api_key=os.getenv("API_KEY")  
        )
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
        graph.add_node("process_scan_result", self.process_scan_result)
        graph.add_node("get_service_name", self.get_service_name)
        graph.add_node("master_choose_script", self.master_choose_script)
        graph.add_node("scan_with_recommanded_scripts", self.scan_with_recommanded_scripts)
        graph.add_node("analyze_scripts_results", self.analyze_scripts_results)

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


        graph.add_edge("get_full_scan", "process_scan_result")
        graph.add_edge("get_os_scan", "process_scan_result")
        graph.add_edge("get_default_scan", "process_scan_result")
        graph.add_edge("process_scan_result", "get_service_name")
        graph.add_edge("get_service_name", "master_choose_script")
        graph.add_edge("master_choose_script", "scan_with_recommanded_scripts")
        graph.add_edge("scan_with_recommanded_scripts", "analyze_scripts_results")

        return graph.compile()  
    
    def get_service_name(self, state: AgentState) -> AgentState:
        """
        Get Service Name from JSON output
        """

        output_file = "nmap_scan_result.json"


        with open(output_file, "r", encoding="utf-8") as json_file:
            parsed_nmap = json.load(json_file)

        print(parsed_nmap)

        open_services = NmapTools.get_script.invoke({"parsed_result": parsed_nmap})


        print(f"[+] - Services détectés : {open_services}")

        state["available_scripts"] = open_services.get("available_scripts", {})
        state["open_services"] = open_services.get("open_services", {})
        
        return state


    def parse_nmap_output(self, nmap_result: str, output_file="nmap_scan_result.json") -> dict:
        """
        Parse the Nmap output from XML to a dictionary.
        """
        try:
            xml_data = nmap_result.stdout.strip()
            
            if not xml_data.startswith("<?xml"):
                raise ValueError("Nmap output does not appear to be valid XML.")
            
            parsed_output = xmltodict.parse(xml_data)

            json_output = json.dumps(parsed_output, indent=4)

            with open(output_file, "w", encoding="utf-8") as json_file:
                json_file.write(json_output)
                

            return json.loads(json_output)

        except Exception as e:
            print(f"[!] - Error parsing Nmap output: {e}")
            return {"error": str(e)}

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
    
    def process_scan_result(self, state: AgentState) -> AgentState:
        """
        Process the scan result by parsing it and analyzing it with an expert agent.
        """

        scan_result = state.get("scan_result", "")

        if not scan_result:
            print("[!] - No scan result available for processing.")
            state["analysis_result"] = "Error: No scan result found."
            return state

        parsed_result = self.parse_nmap_output(scan_result)

        parsed_result_str = json.dumps(parsed_result, indent=4)
        scan_type = state.get("response", "default_scan")
        analysis_result = NmapTools.analyze_nmap_result.invoke({
            "scan_result_json": parsed_result_str,
            "scan_type": scan_type
        })


        tool_call_message = AIMessage(
            content=analysis_result,  
            tool_calls=[{
                "name": "process_scan_result",
                "args": {"scan_result": parsed_result_str, "scan_type": scan_type}, 
                "id": "tool_call_4",
                "type": "tool_call",
            }]
        )

    
        state["analysis_result"] = analysis_result
        state["messages"].append(tool_call_message)

        print(f"[+] - Analysis Summary:\n{analysis_result}")

        return state
    
    def master_choose_script(self, state: AgentState) -> AgentState:
        available_scripts = state.get("available_scripts", {})


        if not available_scripts:
            print("[!] - No available scripts found. Summary: " + state.get("analysis_result", ""))
            return state
            
        choosen_scripts = NmapTools.master_service_choose.invoke({
            "scan_result": json.dumps(state.get("open_services", {}), indent=2),
            "script": state.get("available_scripts", {})
        })

        tool_call_message = AIMessage(
            content=choosen_scripts,
            tool_calls=[{
                "name": "master_service_choose",
                "args": {
                    "scan_result": json.dumps(state.get("open_services", {}), indent=2),
                    "script": state.get("available_scripts", {})
                },
                "id": "tool_call_5",
                "type": "tool_call",
            }]
        )

        state["choosen_scripts"] = choosen_scripts

        return state

    def scan_with_recommanded_scripts(self, state: AgentState) -> AgentState:
        """
        Send the recommended scripts to the user.
        """
        choosen_scripts_str = state.get("choosen_scripts", {})
        if not choosen_scripts_str:
            print("[!] - No recommended scripts found")
            return state

        choosen_scripts = json.loads(choosen_scripts_str)

        print(f"[+] - Recommended scripts: {choosen_scripts}")

        result_scan_scripts = NmapTools.run_recommanded_script.invoke({
            "ip": state.get("ip", "Unknown"),
            "scripts": choosen_scripts,
            "open_services": state.get("open_services", {})
        })

        tool_call_message = AIMessage(
            content=result_scan_scripts,
            tool_calls=[{
                "name": "scan_with_recommanded_scripts",
                "args": {
                    "ip": state.get("ip", "Unknown"),
                    "scripts": choosen_scripts,
                    "open_services": state.get("open_services", {})
                },
                "id": "tool_call_6",
                "type": "tool_call",
            }]
        )

        print(f"[+] - Scan result with recommended scripts: {result_scan_scripts}")
        state["result_scan_scripts"] = result_scan_scripts
        state["messages"].append(tool_call_message)

        return state

    def analyze_scripts_results(self, state: AgentState) -> AgentState:
        """
        Analyze the results of the scripts.
        """
        result_scan_scripts = state.get("result_scan_scripts", "")
        if not result_scan_scripts:
            print("[!] - No scan result available for processing.")
            state["analysis_result"] = "Error: No scan result found."
            return state

        print(f"[+] - Analyzing scan result with scripts: {result_scan_scripts}")


        try:
            if isinstance(result_scan_scripts, str):
                result_scan_scripts = json.loads(result_scan_scripts)

            result_summary_script = NmapTools.analyze_scripts_results.invoke({
                "scan_result_script": result_scan_scripts
            })

            tool_call_message = AIMessage(
                content=result_summary_script,
                tool_calls=[{
                    "name": "analyze_scripts_results",
                    "args": {"scan_result_script": result_scan_scripts},
                    "id": "tool_call_7",
                    "type": "tool_call",
                }]
            )

            print(f"[+] - Analysis Summary:\n{result_summary_script}")
            state["analysis_result"] = result_summary_script
            state["messages"].append(tool_call_message)

            return state

        except Exception as e:
            print(f"[!] - Error analyzing script scan result: {e}")
            state["analysis_result"] = f"Exception: {e}"
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
        state["scan_result"] = result_scan

        return state

    def get_os_scan(self, state: AgentState) -> AgentState:
        """
        Run an OS detection scan on the target IP.
        """
        ip = state.get("ip", "Unknown")
        print(f"[+] - Running OS detection scan on {ip}...")

        result_scan = NmapTools.os_detection_scan.invoke(ip)

        tool_call_message = AIMessage(
            content="",
            tool_calls=[{
                "name": "get_os_scan",
                "args": {"ip": ip},
                "id": "tool_call_4",
                "type": "tool_call",
            }]
        )

        print(f"[+] - Scan result (OS detection): {result_scan}")
        state["scan_result"] = result_scan
        state["messages"].append(tool_call_message)

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

agent.ask("Can you scan IP 192.168.1.26")
from langgraph.graph import StateGraph, START
from agent.state import AgentState

class GraphBuilder:
    def __init__(self, agent):
        """
        Initialise avec un agent (LLMAgent) pour accéder aux fonctions qu'on relie aux nodes
        """
        self.agent = agent

    def build(self):
        graph = StateGraph(AgentState)

        graph.add_node("get_ip", self.agent.get_ip)
        graph.add_node("get_scan_type", self.agent.get_scan_type)
        graph.add_node("get_full_scan", self.agent.get_full_scan)
        graph.add_node("get_default_scan", self.agent.get_default_scan)
        graph.add_node("get_os_scan", self.agent.get_os_scan)
        graph.add_node("process_scan_result", self.agent.process_scan_result)
        graph.add_node("get_service_name", self.agent.get_service_name)
        graph.add_node("master_choose_script", self.agent.master_choose_script)
        graph.add_node("scan_with_recommanded_scripts", self.agent.scan_with_recommanded_scripts)
        graph.add_node("analyze_scripts_results", self.agent.analyze_scripts_results)

        graph.add_edge(START, "get_ip")  
        graph.add_edge("get_ip", "get_scan_type")

        graph.add_conditional_edges(
            "get_scan_type",
            self.agent.route_scan,
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

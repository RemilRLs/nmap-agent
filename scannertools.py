from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode

import re

class NmapTools:
    """
    Class to enumerate every Nmap tools
    """

    llm = ChatOllama(model="llama3.1", base_url="http://localhost:11434")

    @tool 
    def grep_ip(user_input: str):
        """
        Return the IP address from the user input

        :param user_input: User input 
        :return: Extracted IP address or "Unknown" if none found.
        """

        ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

        match_v4 = re.search(ipv4_pattern, user_input)


        if match_v4:
            return match_v4.group()
        else:
            return "Unknown"

    @tool 
    def get_scan_type(user_input: str):
        """
        Return the scan type from the user input

        :param user_input: User input

        :return: Scan type or "Unknown" if none found.
        """


        prompt = f"""
        You are an AI assistant that identifies network scan types based on user input.
        Your task is to determine whether the request is for:
        - An **OS scan** (if the user asks about detecting an operating system).
        - A **full scan** (if the user wants to scan all ports or perform a deep analysis).
        - A **default scan** (if the request is unclear or doesn't match the above categories).

        ### **User request:**
        "{user_input}"

        ### **Respond only with one of the following options:**
        - os_detection_scan
        - full_scan
        - default_scan
        """
        response = NmapTools.llm.invoke(prompt).content.strip()

        if response not in ["os_detection_scan", "full_scan", "default_scan"]:
            return "default_scan"  # Fallback in case of incorrect output
        
        return response

    @tool
    def os_detection_scan(ip: str):
        """Detect operating system of the host.
        TODO : FAIRE EN SORTE DE DETECTER SI L'UTILISATEUT VEUT UN SCAN OS OU UN SCAN DE PORTS
        """
        # implémentation ici

    @tool
    def full_scan(ip: str):
        """Perform an extensive nmap scan."""
        # implémentation ici

    @classmethod
    def get_tool_node(cls):
        """
        Return list of tools for scan
        """
        tools = [
            cls.grep_ip,
            cls.get_scan_type, 
            cls.os_detection_scan,
            cls.full_scan
        ]
        return ToolNode(tools)

ip = NmapTools.grep_ip.invoke("Scan the IP 10.168.1.1")
type_scan = NmapTools.get_scan_type.invoke("Can you scan the OS on the IP 10.168.1.1")

print(type_scan)
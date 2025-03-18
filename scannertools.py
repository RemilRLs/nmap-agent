from langchain_ollama import ChatOllama
from langchain_core.tools import tool, ToolException
from langgraph.prebuilt import ToolNode

import re
import json
import subprocess

class NmapTools:
    """
    Class to enumerate every Nmap tools
    """

    llm = ChatOllama(model="llama3.1", base_url="http://localhost:11434")

    @tool
    def grep_ip(user_input: str):
        """
        Extracts an IP address from the user input.
        """
        try:
            ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            match_v4 = re.search(ipv4_pattern, user_input)
            if match_v4:
                return match_v4.group()
            return "Unknown"
        except Exception as e:
            raise ToolException(f"Error extracting IP: {str(e)}")

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
        - An **OS scan** (`os_detection_scan`) if the user asks about detecting an operating system.
        - A **full scan** (`full_scan`) if the user wants to scan all ports or perform a deep analysis.
        - A **default scan** (`default_scan`) if the request is unclear or doesn't match the above categories.

        ⚠️ **IMPORTANT**: Your response must be **only one** of the following:
        - os_detection_scan
        - full_scan
        - default_scan

        No extra words, explanations, or formatting.

        ### **User request:**
        "{user_input}"

        ### **Your response:**
        """
        response = NmapTools.llm.invoke(prompt).content.strip()

        if response not in ["os_detection_scan", "full_scan", "default_scan"]:
            return "default_scan"  # Fallback in case of incorrect output
        
        return response

    @tool
    def os_detection_scan(ip: str):
        """Detect operating system of the host.
        """
        # implémentation ici

    @tool
    def full_scan(ip: str):
        """Perform an extensive nmap scan."""
        
        try:
            command = ["sudo", "nmap", "-sS", "-p-", ip]

            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                raise ToolException(f"Error executing nmap: {result.stderr}")
            
            return result

        except Exception as e:
            raise ToolException(f"Error executing nmap: {str(e)}")

    @tool 
    def default_scan(ip: str):
        """
        Something
        """
        try:
            command = ["sudo", "nmap", "-sS", "-sV", "-p-", ip]

            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                raise ToolException(f"Error executing nmap: {result.stderr}")
            
            return result

        except Exception as e:
            raise ToolException(f"Error executing nmap: {str(e)}")


    @classmethod
    def get_tool_node(cls):
        """
        Return list of tools for scan
        """

        tools = [
            cls.grep_ip,
            cls.get_scan_type, 
            cls.os_detection_scan,
            cls.full_scan,
            cls.default_scan
        ]
        return ToolNode(tools)

#ip = NmapTools.grep_ip.invoke("Scan the IP 192.168.1.26")
#type_scan = NmapTools.get_scan_type.invoke("Can you scan the OS on the IP 10.168.1.1")

#full_scan = NmapTools.full_scan.invoke(ip)
#print(full_scan)
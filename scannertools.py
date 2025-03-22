from langchain_openai import ChatOpenAI
from langchain_core.tools import tool, ToolException
from langgraph.prebuilt import ToolNode

from typing import Dict, Any

import re
import json
import subprocess
import os
import xmltodict

class NmapTools:
    """
    Class to enumerate every Nmap tools
    """

    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0,
        openai_api_key=os.getenv("API_KEY")  
    )

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
    def analyze_nmap_result(scan_result_json: str) -> str:
        """
        Analyze a structured Nmap scan result (JSON) and provide insights.
        """

        try:
            prompt = f"""
            You are a cybersecurity expert specialized in network security. Your task is to analyze the following Nmap scan result and provide a structured security assessment.

            ### **Scan Report**
            

            {scan_result_json}



            ### **Instructions**
            1. **Summary:** Provide a concise summary of the scanned host(s), including open ports and detected services.
            2. **Security Risks:** Identify potential security risks based on the open ports and services detected.
            3. **Recommended Actions:** Suggest mitigation actions for any detected risks.
            4. **Additional Insights:** If applicable, mention any unusual behaviors, outdated software versions, or vulnerable services.

            ### **Your Response Format**
            - **Host Information**: [IP Address, Hostname if available]
            - **Open Ports & Services**:
              - Port 22 (SSH): OpenSSH 9.6p1 - Secure? [Yes/No]
              - Port 80 (HTTP): Apache 2.4.58 - Secure? [Yes/No]
              - ...
            - **Security Risks**:
              - Risk 1: [Explanation]
              - Risk 2: [Explanation]
            - **Recommended Actions**:
              - Action 1: [Mitigation step]
              - Action 2: [Mitigation step]
            - **Additional Observations**: [Any anomalies detected]

            🚨 **IMPORTANT:** Only return the structured analysis, **no extra explanations** outside the requested format.
            """

            response = NmapTools.llm.invoke(prompt).content.strip()
            return response

        except Exception as e:
            raise ToolException(f"Error analyzing Nmap scan result: {str(e)}")

    @tool
    def get_script(parsed_result: dict) -> dict:
        """
        Extracts open services and their ports from parsed Nmap result.
        Returns a dict like: {'http': 80, 'smtp': 25, ...}
        """
        script_file = "./scripts_nmap/scripts.json"
        services = {}
        services_available = {}

        try:
            ports = parsed_result["nmaprun"]["host"]["ports"]["port"]
            if isinstance(ports, dict): 
                ports = [ports]

            for port in ports:
                if port.get("state", {}).get("@state") == "open":
                    service = port.get("service", {})
                    name = service.get("@name", "").lower()
                    port_id = int(port["@portid"])
                    if name:
                        services[name] = port_id

            with open(script_file, "r") as f:
                scripts = json.load(f)

            for service, port in services.items():
                if service in scripts:
                    services_available[service] = {
                        "port": port,
                        "scripts": scripts[service]["scripts"],
                        "description": scripts[service]["description"]
                    }

            return {
                "open_services": services,
                "available_scripts": services_available
            }

        except Exception as e:
            print(f"[!] - Error extracting services or matching scripts: {e}")
            return {"error": str(e)}


    @tool
    def master_service_choose(scan_result: str, script: Dict[str, Any]) -> str:        
        """
        Choose the most relevant Nmap scripts for each detected service.
        """
        try:
            print(f"Scan result: {scan_result}")

            prompt = f"""
            You are a network security expert. The following services have been detected on a target host:

            [SCANNED SERVICES]
            {scan_result}

            Below is a list of available Nmap scripts for each service, along with their descriptions:

            [SCRIPT LIBRARY]
            {json.dumps(script, indent=2)}

            Your task:
            1. Select the most relevant Nmap scripts to run for each detected service.
            2. Justify each selected script.
            3. If no script applies, return an empty list.

            ⚠️ Rules:
            - Use only the scripts listed.
            - Return the output in the following JSON format:

            {{
            "http": {{
                "scripts": ["http-title", "http-methods"],
                "reason": "Justification for selecting these scripts."
            }},
            "smtp": {{
                "scripts": [],
                "reason": "No script needed."
            }}
            }}

            DO NOT return anything except this JSON.
            """

            print(prompt)
            response = NmapTools.llm.invoke(prompt).content.strip()
            print(response)
            return response
        except Exception as e:
            raise ToolException(f"Error analyzing Nmap scan result: {str(e)}")


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
            command = ["sudo", "nmap", "-sS", "-sV", "-p-", "-oX", "-", ip]

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
            cls.default_scan,
            cls.analyze_nmap_result,
            cls.get_script,
            cls.master_service_choose
        ]
        return ToolNode(tools)
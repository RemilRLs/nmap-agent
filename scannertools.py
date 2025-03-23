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
    def analyze_nmap_result(scan_result_json: str, scan_type: str = "default_scan") -> str:
        """
        Analyze a structured Nmap scan result (JSON) and provide insights.
        """

        try:
            if scan_type == "os_detection_scan":
                prompt = f"""
                You are a cybersecurity analyst specialized in fingerprinting and OS reconnaissance.
                You are analyzing the result of an **OS Detection Nmap Scan (-O)**.

                ### **Scan Report**
                {scan_result_json}

                ### **Instructions**
                1. Extract the most probable OS name and version.
                2. Include additional details: OS vendor, family, generation, uptime, distance (TTL).
                3. Highlight if the OS is outdated or unsupported (if known).
                4. Provide potential risks associated with this OS version (e.g., kernel vulnerabilities).
                5. Suggest remediation or further checks (e.g., CVE lookup, patching).

                ### **Response Format**
                - **Detected OS**: [e.g., Linux 2.6.32, accuracy: 100%]
                - **Vendor / Family / Gen**: [e.g., Linux / Linux / 2.6.X]
                - **Uptime**: [e.g., 35 days]
                - **Distance (TTL estimate)**: [e.g., 0 hop]
                - **Security Assessment**:
                - [Risk or weakness]
                - **Recommended Actions**:
                - [Step 1]
                - [Step 2]

                🚨 Do not add extra explanations. Only return the structured result above.
                """

            else:  # default_scan, full_scan, etc.
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
                - **Security Risks**:
                - Risk 1: [...]
                - **Recommended Actions**:
                - Action 1: [...]
                - **Additional Observations**: [...]

                🚨 Only return the structured analysis above.
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
    def run_recommanded_script(scripts: dict, ip: str, open_services: dict) -> str:
        """
        Run the recommended Nmap scripts for each detected service and return parsed results.
        """
        import subprocess
        import xmltodict
        import json

        print(f"Scripts: {scripts}")
        print(f"Open Services: {open_services}")
        print(f"IP: {ip}")

        results_by_service = {}

        for service, data in scripts.items():
            selected_scripts = data.get("scripts", [])
            if not selected_scripts:
                continue

            port = open_services.get(service)
            if not port:
                continue

            script_list = ",".join(selected_scripts)

            command = [
                "sudo",
                "nmap",
                "-sS",
                "-sV",
                "-p", str(port),
                f"--script={script_list}",
                "-oX", "-", 
                ip
            ]

            try:
                print(f"[>] Running: {' '.join(command)}")
                result = subprocess.run(command, capture_output=True, text=True, check=True)

                xml_output = result.stdout
                parsed = xmltodict.parse(xml_output)

                results_by_service[service] = {
                    "port": port,
                    "scripts": selected_scripts,
                    "parsed_output": parsed
                }

            except subprocess.CalledProcessError as e:
                results_by_service[service] = {
                    "port": port,
                    "scripts": selected_scripts,
                    "error": e.stderr.strip()
                }
            except Exception as e:
                results_by_service[service] = {
                    "port": port,
                    "scripts": selected_scripts,
                    "error": str(e)
                }


        return json.dumps(results_by_service, indent=2)


    @tool
    def os_detection_scan(ip: str) -> str:
        """
        Run Nmap OS detection scan on the target.
        """
        import subprocess

        try:
            command = ["sudo", "nmap", "-O", "-oX", "-", ip] 
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result 
        except subprocess.CalledProcessError as e:
            return f"Error running OS detection: {e.stderr.strip()}"
        except Exception as e:
            return f"Unexpected error: {str(e)}"

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
            cls.master_service_choose,
            cls.run_recommanded_script,
        ]
        return ToolNode(tools)
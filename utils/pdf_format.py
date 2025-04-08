from datetime import datetime
from agent.state import AgentState

import pdfkit
import markdown


class PDFFormat:
    def __init__(self, state):
        self.state = state
        self.current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    def generate_markdown(self) -> str:
        with open("./result/scan_analysis_result.txt", "r") as f1, \
             open("./result/scan_result_script.txt", "r") as f2:
            port_scan = f1.read()
            script_scan = f2.read()

        ip = self.state.get("ip", "N/A")
        #hostname = self.state.get("hostname", "Unknown")

        return f"""# Nmap Scan Report

        ## 1. Target Information
        - IP: {ip}
        - Hostname: 
        - Date: {self.current_time}

        ## 2. Port Scan Summary
        {port_scan.strip()}


        ## 3. Script Scan Summary
        {script_scan.strip()}
        """

    def convert_to_pdf(self, markdown_text: str, output_path: str = "./result/report.pdf"):
        html_content = markdown.markdown(markdown_text)

        full_html = f"""
        <html>
        <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 30px;
                font-size: 12pt;
                color: #333;
            }}
            h1 {{
                color: #007acc;
                font-size: 24pt;
            }}
            h2 {{
                color: #333;
                font-size: 18pt;
                border-bottom: 1px solid #ddd;
                padding-bottom: 5px;
            }}
            code {{
                background-color: #f4f4f4;
                padding: 2px 4px;
                border-radius: 4px;
                font-family: monospace;
            }}
        </style>
        </head>
        <body>
        {html_content}
        </body>
        </html>
        """

        pdfkit.from_string(full_html, output_path)
        print(f"[+] PDF report generated at {output_path}")

    def run(self) -> AgentState:
        md = self.generate_markdown()
        self.convert_to_pdf(md)
        return self.state
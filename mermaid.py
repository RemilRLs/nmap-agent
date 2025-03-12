import os 
from langgraph.graph import StateGraph
from pyppeteer import launch
import asyncio

class MermaidGraphGenerator:
    def __init__(self, state_graph: StateGraph, output_html="graph_mermaid.html", output_png="graph.png"):
        """
        Class to generate graph with Mermaid to visualize the StateGraph (LangGraph)

        :param state_graph: StateGraph
        :param output_html: Output HTML file name
        :param output_png: Output PNG file name
        """

        self.state_graph = state_graph
        self.output_html = output_html
        self.output_png = output_png
        self.mermaid_code = self.state_graph.get_graph().draw_mermaid()


    def generate_html(self):
        """
        Generate HTML content with Mermaid
        """
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <script type="module">
                    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
                mermaid.initialize({{ startOnLoad: true }});
            </script>
        </head>
        <body>
            <pre class="mermaid">
            {self.mermaid_code}
            </pre>
        </body>
        </html>
        """

        # I save it

        with open(self.output_html, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] - The Mermaid Graph have been generated and saved in {self.output_html}")

        
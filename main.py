from agent.llm_agent import LLMAgent

def main():
    print("Welcome to the Nmap LLM Scanner")
    
    user_input = input(">> Please enter your scan request (e.g., 'Scan IP 192.168.1.100'): ")

    agent = LLMAgent() 

    agent.ask("Can you scan IP 192.168.1.26")  

if __name__ == "__main__":
    main()

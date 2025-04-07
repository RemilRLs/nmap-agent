import xmltodict
import json

def parse_nmap_output(nmap_result: str, output_file="nmap_scan_result.json") -> dict:
    try:
        xml_data = nmap_result.stdout.strip()
        if not xml_data.startswith("<?xml"):
            raise ValueError("Nmap output is not valid XML")
        
        parsed = xmltodict.parse(xml_data)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(parsed, f, indent=4)
        return parsed
    except Exception as e:
        return {"error": str(e)}

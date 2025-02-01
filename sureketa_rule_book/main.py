import os
import json
import google.generativeai as genai

# Load existing patterns and rulebook
PATTERNS_FILE = "patterns.json"
RULEBOOK_FILE = ".\\features\\features.json"

# Load JSON files
def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return {}

# Function to extract patterns from the loaded patterns file
def extract_patterns(data):
    extracted_patterns = []

    # Extract relevant protocols and IPs
    for protocol, count in data.get("protocols", {}).items():
        for src_ip_list in data.get("src_ips", {}).values():
            # Ensure we handle the case where the value is not a string but an integer
            if isinstance(src_ip_list, str):
                src_ips = src_ip_list.strip("[]").split(",")  # Extract list of IPs
            elif isinstance(src_ip_list, int):
                src_ips = [str(src_ip_list)]  # Convert integer to string IP
            else:
                src_ips = []

            for src_ip in src_ips:
                for dest_ip_list in data.get("dest_ips", {}).values():
                    # Handle similar case for destination IPs
                    if isinstance(dest_ip_list, str):
                        dest_ips = dest_ip_list.strip("[]").split(",")  # Extract list of IPs
                    elif isinstance(dest_ip_list, int):
                        dest_ips = [str(dest_ip_list)]  # Convert integer to string IP
                    else:
                        dest_ips = []

                    for dest_ip in dest_ips:
                        pattern = {
                            "protocol": protocol,
                            "src_ip": src_ip.strip(),  # Remove any surrounding spaces
                            "dest_ip": dest_ip.strip(),  # Remove any surrounding spaces
                            "src_port": "any",  # Default placeholder
                            "dest_port": "any",  # Default placeholder
                            "content": "malicious_payload"  # Default placeholder
                        }
                        extracted_patterns.append(pattern)
    
    return extracted_patterns

# Load patterns and rulebook
data = load_json(PATTERNS_FILE)  # Loaded patterns from patterns.json
patterns = extract_patterns(data)  # Extracted patterns from the data
rulebook = load_json(RULEBOOK_FILE)  # Existing rules from the rulebook

# Configure Gemini AI
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", "AIzaSyBARRjs8PFYj7xZR0nuiW0cfqEfiKixuuM"))

generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

model = genai.GenerativeModel(
    model_name="gemini-2.0-flash-exp",
    generation_config=generation_config,
    system_instruction="You are a network security expert generating Suricata rules based on flagged botnet traffic.\n"
                        "Use historical rulebook data and identified patterns to ensure consistency in rule generation.\n"
                        "### Context:\n- If a flagged packet matches a known pattern, modify a similar rule.\n"
                        "- If no pattern matches, generate a new rule.\n"
                        "### Rule Format:\n"
                        "`alert <protocol> <src_ip> <src_port> -> <dest_ip> <dest_port> (msg:\"<message>\"; content:\"<content>\"; sid:<sid>;)`\n",
)

# Function to find a matching pattern
def find_matching_pattern(packet_data):
    print("Type of packet_data:", type(packet_data))
    print("Packet Data Content:", packet_data)

    # Check if the packet_data is in string format and load if needed
    if isinstance(packet_data, str):  # If it's a JSON string, convert it
        packet_data = json.loads(packet_data)

    # Loop through patterns and find a match (with more flexibility)
    for pattern in patterns:
        print(f"Matching {packet_data} with {pattern}")

        # Check if there's a match on protocol, or if protocol is unspecified
        protocol_match = packet_data["protocol"] == pattern["protocol"] or pattern["protocol"] == "ip"

        # Check if source and destination IPs match
        ip_match = packet_data["src_ip"] == pattern["src_ip"] or packet_data["dest_ip"] == pattern["dest_ip"]

        # Check if content matches
        content_match = packet_data["content"] == pattern["content"]

        if protocol_match and ip_match and content_match:
            return pattern
    
    return None # No match found

# Function to check if the rule already exists
def rule_exists(new_rule):
    for rule in rulebook.get("rules", []):
        if new_rule.strip() == rule.strip():
            return True
    return False

# Function to generate or modify a rule
def generate_rule(packet_data):
    matched_pattern = find_matching_pattern(packet_data)
    
    # Construct user prompt with matched pattern
    user_input = f"### User Input (Flagged Packet Data):\n{json.dumps(packet_data, indent=2)}\n\n"
    
    if matched_pattern:
        user_input += f"### Matched Pattern Found:\n{json.dumps(matched_pattern, indent=2)}\n"
        user_input += "- Modify the pattern to fit the flagged packet data.\n"
    else:
        user_input += "- No matching pattern found. Generate a new Suricata rule.\n"
    
    # Generate rule using Gemini AI
    response = model.generate_content(user_input)
    generated_rule = response.text.strip()

    # Check if the rule already exists in the rulebook
    if rule_exists(generated_rule):
        print("Rule already exists in rulebook.")
        return generated_rule

    # Save new rule to rulebook
    rulebook.setdefault("rules", []).append(generated_rule)
    with open(RULEBOOK_FILE, "w") as f:
        json.dump(rulebook, f, indent=2)
    
    print("New rule added to rulebook.")
    return generated_rule

# Example packet from botnet detection
flagged_packet = {
    "sid": "20002",
    "src_ip": "10.0.0.50",
    "src_port": "443",
    "dest_ip": "192.168.1.10",
    "dest_port": "80",
    "protocol": "tcp",
    "content": "new_malicious_payload",
    "timestamp": "2025-02-02T15:10:00Z",
    "alert_type": "alert"
}

# Generate rule based on flagged packet
new_rule = generate_rule(flagged_packet)
print("\nGenerated Suricata Rule:\n", new_rule)

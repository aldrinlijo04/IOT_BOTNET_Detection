import os

# Set the log level to suppress INFO and DEBUG messages
os.environ['GLOG_minloglevel'] = '2'
import json
import google.generativeai as genai

# Load existing patterns and rulebook
PATTERNS_FILE = "patterns.json"
RULEBOOK_FILE = ".\\features\\features.json"
SURICATA_RULES_FILE = r"C:\Users\SEC\Desktop\GIT HUB\BOLT\IOT_BOTNET_Detection\IOT_BOTNET_Detection\sureketa_rule_book\rulebook\suricata.rules"

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
import random

def find_matching_pattern(packet_data):
    # Check if the packet_data is in string format and load if needed
    if isinstance(packet_data, str):  # If it's a JSON string, convert it
        packet_data = json.loads(packet_data)

    # Randomize the number of iterations (between 1 and 50)
    max_iterations = random.randint(1, 50)

    # Loop through patterns and find a match, with a random stopping condition
    for i in range(max_iterations):
        # Check if there's a match on protocol, or if protocol is unspecified
        for pattern in patterns:
            protocol_match = packet_data["protocol"] == pattern["protocol"] or pattern["protocol"] == "ip"
            ip_match = packet_data["src_ip"] == pattern["src_ip"] or packet_data["dest_ip"] == pattern["dest_ip"]
            content_match = packet_data["content"] == pattern["content"]

            if protocol_match and ip_match and content_match:
                return pattern  # Return the first match found

    return None  # No match found


# Function to check if the rule already exists
def rule_exists(new_rule):
    # Convert the new_rule to a string in case it's not already
    if isinstance(new_rule, dict):
        new_rule = str(new_rule)

    for rule in rulebook.get("rules", []):
        # Make sure the rule is also a string for comparison
        if isinstance(rule, dict):
            rule = str(rule)

        if new_rule.strip() == rule.strip():
            return True
    return False

def write_to_suricata_rules(rule):
    with open(SURICATA_RULES_FILE, "a") as f:
        f.write(rule + "\n")

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

    # Extract the generated Suricata rule text
    if isinstance(response, dict) and 'text' in response:
        generated_rule = response.result.candidates[0].content.parts[0].text.strip()
    else:
        generated_rule = str(response).strip()  # Handle unexpected response format

    # Check if the rule already exists in the rulebook
    if rule_exists(generated_rule):
        return generated_rule

    # Save new rule to rulebook
    rulebook.setdefault("rules", []).append(generated_rule)
    with open(RULEBOOK_FILE, "w") as f:
        json.dump(rulebook, f, indent=2)

    return generated_rule


# Example packet from botnet detection
flagged_packet = {
  "sid": "20002",
  "src_ip": "10.0.0.50",
  "src_port": "443",
  "dest_ip": "192.168.1.10",
  "dest_port": "80",
  "protocol": "tcp",
  "content": "malicious_payload",
  "timestamp": "2025-02-02T15:10:00Z",
  "alert_type": "alert"
}

# Generate rule based on flagged packet
new_rule = generate_rule(flagged_packet)

# Construct alert message
alert_message = f"alert {flagged_packet['protocol']} {flagged_packet['src_ip']} {flagged_packet['src_port']} -> {flagged_packet['dest_ip']} {flagged_packet['dest_port']} (msg:\"Botnet Traffic Detected\"; content:\"{flagged_packet['content']}\"; sid:{flagged_packet['sid']})"

write_to_suricata_rules(alert_message)
# Output the generated rule and the alert message
print(alert_message)

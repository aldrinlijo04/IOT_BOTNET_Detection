import re
import json
import os

def parse_rule(line):
    """Extracts components from a Suricata rule line."""
    rule_pattern = re.compile(r'^(alert|drop|reject)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.*)\)')
    match = rule_pattern.match(line)
    
    if match:
        action, protocol, src_ip, src_port, dest_ip, dest_port, options = match.groups()
        
        # Extract key-value pairs from options
        options_dict = {}
        option_pairs = re.findall(r'(\w+):?\s*"?([^"]+?)"?;', options)
        for key, value in option_pairs:
            options_dict[key] = value

        return {
            "action": action,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            **options_dict
        }
    return None

def parse_rules_file(file_path):
    """Parses a Suricata .rules file."""
    rules = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                rule_data = parse_rule(line)
                if rule_data:
                    rules.append(rule_data)
    return rules

def parse_map_file(file_path):
    """Parses a .map file to extract SID mappings."""
    sid_map = {}
    with open(file_path, 'r') as f:
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                sid, description = parts
                sid_map[sid] = description
    return sid_map

def parse_text_file(file_path):
    """Extracts meaningful text from a .txt file."""
    with open(file_path, 'r') as f:
        return f.read().strip()

def parse_classification_config(file_path):
    """Parses classification.config to extract rule classifications."""
    classifications = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    classifications[parts[0]] = parts[1]
    return classifications

def process_rule_book(directory):
    """Processes all RULE, MAP, and TEXT files in a directory."""
    data = {"rules": [], "map": {}, "text": {}, "classification": {}}
    
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        
        if file_name.endswith('.rules'):
            data["rules"].extend(parse_rules_file(file_path))
        elif file_name.endswith('.map'):
            data["map"].update(parse_map_file(file_path))
        elif file_name.endswith('.txt'):
            data["text"][file_name] = parse_text_file(file_path)
        elif file_name == 'classification.config':
            data["classification"].update(parse_classification_config(file_path))
    
    return data

def save_to_json(data, filename):
    """Save the data to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def load_from_json(filename):
    """Load data from a JSON file."""
    with open(filename, 'r') as f:
        return json.load(f)

# Process the rule book and save to a JSON file
rule_book_data = process_rule_book(r"C:\Users\SEC\Downloads\sureketa_rule_book\rulebook")
save_to_json(rule_book_data, r"C:\Users\SEC\Downloads\sureketa_rule_book\features\features.json")

# Later, load the JSON file for pattern extraction and rule writing
# loaded_data = load_from_json(r"C:\Users\SEC\Downloads\sureketa_rule_book\features")
# print(loaded_data)

import json
from collections import defaultdict

def save_patterns_to_json(patterns, filename):
    """Saves the identified patterns to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(patterns, f, indent=2)
    print(f"Patterns saved to {filename}")

def load_patterns_from_json(filename):
    """Loads the stored patterns from a JSON file."""
    with open(filename, 'r') as f:
        return json.load(f)

def analyze_rules(rules):
    """Analyze the rules and identify common patterns."""
    actions = defaultdict(int)
    protocols = defaultdict(int)
    src_ips = defaultdict(int)
    src_ports = defaultdict(int)
    dest_ips = defaultdict(int)
    dest_ports = defaultdict(int)
    options = defaultdict(int)

    for rule in rules:
        # Count occurrences of each action
        actions[rule['action']] += 1
        protocols[rule['protocol']] += 1
        src_ips[rule['src_ip']] += 1
        src_ports[rule['src_port']] += 1
        dest_ips[rule['dest_ip']] += 1
        dest_ports[rule['dest_port']] += 1

        # Collect common options
        for key, value in rule.items():
            if key not in ['action', 'protocol', 'src_ip', 'src_port', 'dest_ip', 'dest_port']:
                options[key] += 1

    return {
        "actions": dict(actions),
        "protocols": dict(protocols),
        "src_ips": dict(src_ips),
        "src_ports": dict(src_ports),
        "dest_ips": dict(dest_ips),
        "dest_ports": dict(dest_ports),
        "options": dict(options)
    }

def print_analysis(patterns):
    """Print the analysis results in a readable format."""
    print("\nCommon Actions:")
    for action, count in patterns['actions'].items():
        print(f"  {action}: {count}")

    print("\nCommon Protocols:")
    for protocol, count in patterns['protocols'].items():
        print(f"  {protocol}: {count}")

    print("\nCommon Source IPs:")
    for src_ip, count in patterns['src_ips'].items():
        print(f"  {src_ip}: {count}")

    print("\nCommon Source Ports:")
    for src_port, count in patterns['src_ports'].items():
        print(f"  {src_port}: {count}")

    print("\nCommon Destination IPs:")
    for dest_ip, count in patterns['dest_ips'].items():
        print(f"  {dest_ip}: {count}")

    print("\nCommon Destination Ports:")
    for dest_port, count in patterns['dest_ports'].items():
        print(f"  {dest_port}: {count}")

    print("\nCommon Rule Options:")
    for option, count in patterns['options'].items():
        print(f"  {option}: {count}")

def main():
    # Load the rule book data from the JSON file
    rule_book_file = r"C:\Users\SEC\Downloads\sureketa_rule_book\features\features.json"
    with open(rule_book_file, 'r',encoding='utf-8') as f:
        loaded_data = json.load(f)

    # Analyze the rules in the loaded data
    patterns = analyze_rules(loaded_data["rules"])

    # Save the patterns to a file
    patterns_file = r"C:\Users\SEC\Downloads\sureketa_rule_book\patterns.json"
    save_patterns_to_json(patterns, patterns_file)

    # Optionally, load the patterns back from the file
    # loaded_patterns = load_patterns_from_json(patterns_file)
    # print_analysis(loaded_patterns)

if __name__ == "__main__":
    main()

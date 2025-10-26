# firewall.py
"""
Simple Firewall Rule Simulator
- Rule syntax (one per line in rules.txt):
  ACTION PROTOCOL SRC DST PORT
  ACTION := allow | deny
  PROTOCOL := tcp | udp | icmp | any
  SRC/DST := IP, CIDR (e.g. 192.168.1.0/24) or 'any'
  PORT := number, range (80-90) or 'any' (for tcp/udp). For icmp use 'any'.

Examples:
  allow tcp 192.168.1.0/24 any 80
  deny any any any any

Usage:
  python firewall.py "check" --pkt "tcp 192.168.1.5 8.8.8.8 80"
  python firewall.py --rules rules.txt --batch packets.txt
"""

import argparse
import ipaddress
import sys
from typing import List, Dict, Tuple, Optional


def parse_rule_line(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    parts = line.split()
    if len(parts) != 5:
        raise ValueError(f"Invalid rule format: {line}")
    action, proto, src, dst, port = parts
    action = action.lower()
    proto = proto.lower()
    return {"action": action, "proto": proto, "src": src.lower(), "dst": dst.lower(), "port": port.lower(), "raw": line}


def load_rules(path: str) -> List[Dict]:
    rules = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            parsed = parse_rule_line(line)
            if parsed:
                rules.append(parsed)
    return rules


def ip_matches(net_or_any: str, ip: str) -> bool:
    if net_or_any == "any":
        return True
    try:
        if "/" in net_or_any:
            net = ipaddress.ip_network(net_or_any, strict=False)
            return ipaddress.ip_address(ip) in net
        else:
            return ipaddress.ip_address(ip) == ipaddress.ip_address(net_or_any)
    except ValueError:
        return False


def port_matches(port_expr: str, pkt_port: Optional[int]) -> bool:
    if port_expr == "any":
        return True
    if pkt_port is None:
        return False
    if '-' in port_expr:
        lo, hi = port_expr.split('-', 1)
        return int(lo) <= pkt_port <= int(hi)
    return int(port_expr) == pkt_port


def proto_matches(proto_expr: str, pkt_proto: str) -> bool:
    if proto_expr == "any":
        return True
    return proto_expr.lower() == pkt_proto.lower()


def evaluate_packet(rules: List[Dict], pkt: Dict) -> Tuple[str, Optional[Dict]]:
    """
    Evaluate packet against rules in order.
    Returns (action, matched_rule or None)
    """
    for rule in rules:
        try:
            if not proto_matches(rule["proto"], pkt["proto"]):
                continue
            if not ip_matches(rule["src"], pkt["src"]):
                continue
            if not ip_matches(rule["dst"], pkt["dst"]):
                continue
            if pkt["proto"].lower() in ("tcp", "udp"):
                if not port_matches(rule["port"], pkt["port"]):
                    continue
            # if proto icmp, port is ignored (rule port should be 'any')
            return rule["action"], rule
        except Exception:
            continue
    # default policy: deny
    return "deny", None


def parse_packet_string(s: str) -> Dict:
    """
    Packet format expected for CLI: "tcp 192.168.1.5 8.8.8.8 80"
    For icmp: "icmp 10.0.0.2 8.8.8.8 any"
    """
    parts = s.strip().split()
    if len(parts) != 4:
        raise ValueError("Packet must be: PROTO SRC DST PORT")
    proto, src, dst, port = parts
    proto = proto.lower()
    pkt_port = None
    if proto in ("tcp", "udp"):
        if port.lower() != "any":
            pkt_port = int(port)
    return {"proto": proto, "src": src, "dst": dst, "port": pkt_port}


def load_packets(path: str) -> List[Dict]:
    pkts = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            pkts.append(parse_packet_string(line))
    return pkts


def pretty_rule(rule: Dict) -> str:
    return rule.get("raw", "")


def main():
    parser = argparse.ArgumentParser(description="Simple Firewall Rule Simulator")
    parser.add_argument("--rules", default="rules.txt", help="Path to rules file")
    parser.add_argument("--batch", help="Path to packets file for batch testing")
    parser.add_argument("--pkt", help="Single packet string: 'tcp SRC DST PORT'")
    parser.add_argument("check", nargs='?', help=argparse.SUPPRESS)
    args = parser.parse_args()

    try:
        rules = load_rules(args.rules)
    except FileNotFoundError:
        print(f"Rules file not found: {args.rules}")
        sys.exit(1)
    except Exception as e:
        print("Error loading rules:", e)
        sys.exit(1)

    if args.batch:
        try:
            packets = load_packets(args.batch)
        except FileNotFoundError:
            print("Packets file not found:", args.batch)
            sys.exit(1)
        for i, pkt in enumerate(packets, 1):
            action, matched = evaluate_packet(rules, pkt)
            print(f"[{i}] {pkt['proto'].upper()} {pkt['src']} -> {pkt['dst']} ({pkt['port'] if pkt['port'] is not None else 'any'}) => {action.upper()}")
            if matched:
                print("     matched rule:", pretty_rule(matched))
            else:
                print("     matched rule: <none> (default deny)")
    elif args.pkt:
        try:
            pkt = parse_packet_string(args.pkt)
        except Exception as e:
            print("Error parsing packet:", e)
            sys.exit(1)
        action, matched = evaluate_packet(rules, pkt)
        print(f"{pkt['proto'].upper()} {pkt['src']} -> {pkt['dst']} ({pkt['port'] if pkt['port'] is not None else 'any'}) => {action.upper()}")
        if matched:
            print("matched rule:", pretty_rule(matched))
        else:
            print("matched rule: <none> (default deny)")
    else:
        print("No packet provided. Use --pkt or --batch. See --help.")
        sys.exit(0)


if __name__ == "__main__":
    main()

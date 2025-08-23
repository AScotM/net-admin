import os
import time
import json
import signal
import logging
import socket
import platform
from datetime import datetime
from typing import Dict, List, Optional, Literal, Union
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Constants
COLORS: Dict[str, str] = {
    "ESTABLISHED": Fore.GREEN,
    "SYN_SENT": Fore.RED,
    "SYN_RECV": Fore.RED,
    "LISTEN": Fore.YELLOW,
    "CLOSE": Fore.RED,
    "DEFAULT": Style.RESET_ALL,
    "HEADER": Fore.BLUE + Style.BRIGHT,
    "TIMESTAMP": Fore.CYAN + Style.BRIGHT,
    "SEPARATOR": Fore.LIGHTBLACK_EX,
}

TCP_STATES: Dict[str, str] = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"
}

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_ipv4(hex_ip: str) -> str:
    """Convert hex IPv4 address (little-endian) to dotted decimal format."""
    try:
        return socket.inet_ntop(socket.AF_INET, bytes.fromhex(hex_ip)[::-1])
    except ValueError as e:
        logger.error(f"Failed to parse IPv4: {e}")
        return "0.0.0.0"

def parse_ipv6(hex_ip: str) -> str:
    """Convert hex IPv6 address (little-endian per 32-bit word) to colon-separated format."""
    try:
        # Split into 4-byte (8-char) chunks, reverse each, and join
        chunks = [hex_ip[i:i+8] for i in range(0, 32, 8)][::-1]
        reversed_hex = "".join(chunks)
        return socket.inet_ntop(socket.AF_INET6, bytes.fromhex(reversed_hex))
    except ValueError as e:
        logger.error(f"Failed to parse IPv6: {e}")
        return "::"

def read_tcp_connections(
    protocol: str = "tcp",
    filter_state: Optional[str] = None,
    filter_ip: Optional[str] = None,
    filter_port: Optional[int] = None,
) -> List[Dict[str, Union[str, int]]]:
    """Read and filter TCP connections from /proc/net."""
    # Check if running on Linux
    if platform.system() != "Linux":
        logger.error("This script requires a Linux system with /proc/net.")
        return []

    proc_file = f"/proc/net/{protocol}"
    if not os.path.exists(proc_file):
        logger.error(f"{proc_file} not found. Are you on a Linux system?")
        return []

    connections = []
    try:
        with open(proc_file, "r") as file:
            next(file)  # Skip header
            for line in file:
                fields = line.strip().split()
                if len(fields) < 4 or ":" not in fields[1] or ":" not in fields[2]:
                    logger.warning(f"Skipping malformed line: {line.strip()}")
                    continue

                local_hex, local_port_hex = fields[1].split(":")
                peer_hex, peer_port_hex = fields[2].split(":")
                state_hex = fields[3]
                state = TCP_STATES.get(state_hex, "UNKNOWN")

                try:
                    local_port = int(local_port_hex, 16)
                    peer_port = int(peer_port_hex, 16)
                except ValueError as e:
                    logger.warning(f"Skipping line due to invalid port: {line.strip()}")
                    continue

                local_ip = parse_ipv6(local_hex) if "6" in protocol else parse_ipv4(local_hex)
                peer_ip = parse_ipv6(peer_hex) if "6" in protocol else parse_ipv4(peer_hex)

                # Apply filters
                if filter_state and state != filter_state.upper():
                    continue
                if filter_ip and filter_ip not in (local_ip, peer_ip):
                    continue
                if filter_port and filter_port not in (local_port, peer_port):
                    continue

                connections.append({
                    "protocol": protocol,
                    "state": state,
                    "local_address": local_ip,
                    "local_port": local_port,
                    "peer_address": peer_ip,
                    "peer_port": peer_port,
                })
    except IOError as e:
        logger.error(f"Failed to read {proc_file}: {e}")

    return connections

def display_connections(
    connections: List[Dict[str, Union[str, int]]],
    output_format: Literal["text", "json"] = "text",
) -> None:
    """Display connections in text or JSON format."""
    if output_format == "json":
        class ConnectionEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, int):
                    return str(obj)  # Ensure ports are strings for consistency
                return super().default(obj)
        print(json.dumps(connections, indent=2, cls=ConnectionEncoder))
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f"{COLORS['HEADER']}Netid  State          Local Address:Port     Peer Address:Port{COLORS['DEFAULT']}"
        separator = f"{COLORS['SEPARATOR']}{'=' * 70}{COLORS['DEFAULT']}"

        print(f"{COLORS['TIMESTAMP']}Timestamp: {timestamp}{COLORS['DEFAULT']}")
        print(header)
        print(separator)
        
        for conn in connections:
            color = COLORS.get(conn["state"], COLORS["DEFAULT"])
            line = (
                f"{conn['protocol']:<6} {color}{conn['state']:<14}{COLORS['DEFAULT']} "
                f"{conn['local_address']}:{conn['local_port']:<5}   "
                f"{conn['peer_address']}:{conn['peer_port']:<5}"
            )
            print(line)
            print(f"{COLORS['SEPARATOR']}{'-' * 70}{COLORS['DEFAULT']}")
        
        print(separator)

def watch_tcp_connections(
    interval: int = 2,
    filter_state: Optional[str] = None,
    filter_ip: Optional[str] = None,
    filter_port: Optional[int] = None,
    output_format: Literal["text", "json"] = "text",
) -> None:
    """Continuously monitor TCP connections."""
    def signal_handler(sig: int, frame) -> None:
        logger.info("\nExiting TCP connection watcher.")
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        connections = read_tcp_connections("tcp", filter_state, filter_ip, filter_port)
        connections += read_tcp_connections("tcp6", filter_state, filter_ip, filter_port)
        display_connections(connections, output_format)
        time.sleep(interval)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Monitor TCP connections (IPv4 & IPv6). Example: python script.py --filter-state ESTABLISHED --filter-ip 127.0.0.1 --interval 5"
    )
    parser.add_argument("--interval", type=int, default=2, help="Update interval in seconds")
    parser.add_argument(
        "--filter-state",
        type=str,
        choices=TCP_STATES.values(),
        help="Filter by TCP state (e.g., ESTABLISHED, LISTEN)"
    )
    parser.add_argument("--filter-ip", type=str, help="Filter by IP address")
    parser.add_argument("--filter-port", type=int, help="Filter by port")
    parser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )
    args = parser.parse_args()

    if args.interval <= 0:
        logger.error("Interval must be a positive integer.")
        exit(1)

    watch_tcp_connections(
        args.interval,
        args.filter_state,
        args.filter_ip,
        args.filter_port,
        args.output_format,
    )

import argparse
import os
import pwd
import select
import socket
import sys
import termios
import time
import tty
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"
CLEAR = "\033[2J\033[H"

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

STATE_COLORS = {
    "ESTABLISHED": GREEN,
    "SYN_SENT": YELLOW,
    "SYN_RECV": YELLOW,
    "FIN_WAIT1": YELLOW,
    "FIN_WAIT2": YELLOW,
    "TIME_WAIT": MAGENTA,
    "CLOSE": RED,
    "CLOSE_WAIT": RED,
    "LAST_ACK": RED,
    "LISTEN": BLUE,
    "CLOSING": RED,
    "NEW_SYN_RECV": YELLOW,
}


@dataclass(frozen=True)
class TCPConnection:
    family: str
    slot: str
    local_ip: str
    local_port: int
    peer_ip: str
    peer_port: int
    state: str
    uid: int
    user: str
    inode: int

    @property
    def local_endpoint(self) -> str:
        return format_endpoint(self.local_ip, self.local_port, self.family)

    @property
    def peer_endpoint(self) -> str:
        return format_endpoint(self.peer_ip, self.peer_port, self.family)


@dataclass
class Snapshot:
    timestamp: datetime
    connections: list[TCPConnection]

    def count_state(self, state: str) -> int:
        return sum(1 for connection in self.connections if connection.state == state)

    @property
    def total(self) -> int:
        return len(self.connections)

    @property
    def established(self) -> int:
        return self.count_state("ESTABLISHED")

    @property
    def listening(self) -> int:
        return self.count_state("LISTEN")

    @property
    def time_wait(self) -> int:
        return self.count_state("TIME_WAIT")


class Terminal:
    def __init__(self) -> None:
        self.fd: Optional[int] = None
        self.old_settings = None
        self.interactive = sys.stdin.isatty()

    def __enter__(self):
        if self.interactive:
            self.fd = sys.stdin.fileno()
            self.old_settings = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.interactive and self.fd is not None and self.old_settings is not None:
            termios.tcsetattr(
                self.fd,
                termios.TCSADRAIN,
                self.old_settings,
            )

    def key_pressed(self) -> Optional[str]:
        if not self.interactive:
            return None

        readable, _, _ = select.select([sys.stdin], [], [], 0)

        if not readable:
            return None

        return sys.stdin.read(1)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor Linux TCP connections directly from /proc."
    )

    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=2.0,
        help="Refresh interval in seconds",
    )

    parser.add_argument(
        "-4",
        "--ipv4",
        action="store_true",
        help="Show IPv4 connections only",
    )

    parser.add_argument(
        "-6",
        "--ipv6",
        action="store_true",
        help="Show IPv6 connections only",
    )

    parser.add_argument(
        "-s",
        "--state",
        action="append",
        help="Filter by TCP state",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Filter by local or peer port",
    )

    parser.add_argument(
        "-u",
        "--uid",
        type=int,
        help="Filter by UID",
    )

    parser.add_argument(
        "--user",
        help="Filter by username",
    )

    parser.add_argument(
        "--address",
        help="Filter by local or peer IP address",
    )

    parser.add_argument(
        "--sort",
        choices=[
            "state",
            "local",
            "peer",
            "port",
            "uid",
            "inode",
        ],
        default="state",
        help="Sort connections",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Print one snapshot and exit",
    )

    parser.add_argument(
        "--no-clear",
        action="store_true",
        help="Do not clear the terminal between snapshots",
    )

    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("interval must be greater than zero")

    if args.port is not None and not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")

    if args.uid is not None and args.uid < 0:
        parser.error("UID cannot be negative")

    if args.state:
        normalized_states = []

        for state in args.state:
            state = state.upper()

            if state not in TCP_STATES.values():
                parser.error(f"unknown TCP state: {state}")

            normalized_states.append(state)

        args.state = normalized_states

    return args


def decode_ipv4(hex_ip: str) -> str:
    if len(hex_ip) != 8:
        raise ValueError("invalid IPv4 address length")

    raw = bytes.fromhex(hex_ip)
    return socket.inet_ntop(socket.AF_INET, raw[::-1])


def decode_ipv6(hex_ip: str) -> str:
    if len(hex_ip) != 32:
        raise ValueError("invalid IPv6 address length")

    raw = bytes.fromhex(hex_ip)

    converted = b"".join(
        raw[offset:offset + 4][::-1]
        for offset in range(0, 16, 4)
    )

    return socket.inet_ntop(socket.AF_INET6, converted)


def decode_ip(hex_ip: str, family: str) -> str:
    try:
        if family == "IPv4":
            return decode_ipv4(hex_ip)

        if family == "IPv6":
            return decode_ipv6(hex_ip)

    except (ValueError, OSError):
        return "INVALID"

    return "INVALID"


def resolve_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def parse_endpoint(value: str, family: str) -> tuple[str, int]:
    address_hex, port_hex = value.split(":", 1)

    address = decode_ip(address_hex, family)
    port = int(port_hex, 16)

    return address, port


def parse_connection(line: str, family: str) -> Optional[TCPConnection]:
    fields = line.split()

    if len(fields) < 10:
        return None

    try:
        slot = fields[0].rstrip(":")
        local_ip, local_port = parse_endpoint(fields[1], family)
        peer_ip, peer_port = parse_endpoint(fields[2], family)
        state = TCP_STATES.get(fields[3], f"UNKNOWN({fields[3]})")
        uid = int(fields[7])
        inode = int(fields[9])
        user = resolve_username(uid)

        return TCPConnection(
            family=family,
            slot=slot,
            local_ip=local_ip,
            local_port=local_port,
            peer_ip=peer_ip,
            peer_port=peer_port,
            state=state,
            uid=uid,
            user=user,
            inode=inode,
        )

    except (ValueError, IndexError):
        return None


def read_proc_file(path: str, family: str) -> list[TCPConnection]:
    connections = []

    try:
        with open(path, "r", encoding="ascii") as file:
            next(file, None)

            for line in file:
                connection = parse_connection(line, family)

                if connection is not None:
                    connections.append(connection)

    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    except OSError:
        pass

    return connections


def collect_connections(
    include_ipv4: bool,
    include_ipv6: bool,
) -> list[TCPConnection]:
    connections = []

    if include_ipv4:
        connections.extend(
            read_proc_file(
                "/proc/net/tcp",
                "IPv4",
            )
        )

    if include_ipv6:
        connections.extend(
            read_proc_file(
                "/proc/net/tcp6",
                "IPv6",
            )
        )

    return connections


def filter_connections(
    connections: list[TCPConnection],
    args: argparse.Namespace,
) -> list[TCPConnection]:
    result = []

    for connection in connections:
        if args.state and connection.state not in args.state:
            continue

        if args.port is not None:
            if (
                connection.local_port != args.port
                and connection.peer_port != args.port
            ):
                continue

        if args.uid is not None and connection.uid != args.uid:
            continue

        if args.user is not None:
            if connection.user.lower() != args.user.lower():
                continue

        if args.address is not None:
            needle = args.address.lower()

            if (
                needle not in connection.local_ip.lower()
                and needle not in connection.peer_ip.lower()
            ):
                continue

        result.append(connection)

    return result


def sort_connections(
    connections: list[TCPConnection],
    mode: str,
) -> list[TCPConnection]:
    if mode == "state":
        key = lambda connection: (
            connection.state,
            connection.family,
            connection.local_ip,
            connection.local_port,
        )
    elif mode == "local":
        key = lambda connection: (
            connection.local_ip,
            connection.local_port,
        )
    elif mode == "peer":
        key = lambda connection: (
            connection.peer_ip,
            connection.peer_port,
        )
    elif mode == "port":
        key = lambda connection: (
            connection.local_port,
            connection.peer_port,
        )
    elif mode == "uid":
        key = lambda connection: (
            connection.uid,
            connection.local_port,
        )
    elif mode == "inode":
        key = lambda connection: connection.inode
    else:
        key = lambda connection: connection.state

    return sorted(connections, key=key)


def format_endpoint(ip: str, port: int, family: str) -> str:
    if family == "IPv6":
        return f"[{ip}]:{port}"

    return f"{ip}:{port}"


def colorize(
    text: str,
    color: str,
    enabled: bool,
) -> str:
    if not enabled:
        return text

    return f"{color}{text}{RESET}"


def state_color(state: str) -> str:
    return STATE_COLORS.get(state, RED)


def terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 120


def truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value

    if width <= 3:
        return value[:width]

    return value[:width - 3] + "..."


def display_header(
    snapshot: Snapshot,
    color_enabled: bool,
    interval: float,
) -> None:
    timestamp = snapshot.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    title = colorize(
        "TCP CONNECTION MONITOR",
        CYAN + BOLD,
        color_enabled,
    )

    print(title)
    print(
        f"{timestamp}  "
        f"refresh={interval:g}s  "
        f"total={snapshot.total}  "
        f"established={snapshot.established}  "
        f"listen={snapshot.listening}  "
        f"time_wait={snapshot.time_wait}"
    )
    print()


def display_state_summary(
    connections: list[TCPConnection],
    color_enabled: bool,
) -> None:
    counts = {}

    for connection in connections:
        counts[connection.state] = counts.get(connection.state, 0) + 1

    if not counts:
        return

    pieces = []

    for state in sorted(counts):
        text = f"{state}:{counts[state]}"
        pieces.append(
            colorize(
                text,
                state_color(state),
                color_enabled,
            )
        )

    print("States: " + "  ".join(pieces))
    print()


def display_connections(
    connections: list[TCPConnection],
    color_enabled: bool,
) -> None:
    width = terminal_width()

    local_width = 39 if width >= 130 else 28
    peer_width = 39 if width >= 130 else 28
    user_width = 16 if width >= 120 else 12

    header = (
        f"{'IP':<4} "
        f"{'STATE':<14} "
        f"{'LOCAL':<{local_width}} "
        f"{'PEER':<{peer_width}} "
        f"{'USER':<{user_width}} "
        f"{'UID':>6} "
        f"{'INODE':>10}"
    )

    print(colorize(header, YELLOW, color_enabled))
    print("-" * min(len(header), max(width, 80)))

    if not connections:
        print(colorize("No matching TCP connections.", DIM, color_enabled))
        return

    for connection in connections:
        family = "v4" if connection.family == "IPv4" else "v6"

        state = colorize(
            f"{connection.state:<14}",
            state_color(connection.state),
            color_enabled,
        )

        local = truncate(
            connection.local_endpoint,
            local_width,
        )

        peer = truncate(
            connection.peer_endpoint,
            peer_width,
        )

        user = truncate(
            connection.user,
            user_width,
        )

        print(
            f"{family:<4} "
            f"{state} "
            f"{local:<{local_width}} "
            f"{peer:<{peer_width}} "
            f"{user:<{user_width}} "
            f"{connection.uid:>6} "
            f"{connection.inode:>10}"
        )


def display_family_summary(
    connections: list[TCPConnection],
) -> None:
    ipv4 = sum(
        1
        for connection in connections
        if connection.family == "IPv4"
    )

    ipv6 = sum(
        1
        for connection in connections
        if connection.family == "IPv6"
    )

    print()
    print(f"IPv4: {ipv4}  IPv6: {ipv6}")


def create_snapshot(args: argparse.Namespace) -> Snapshot:
    include_ipv4 = True
    include_ipv6 = True

    if args.ipv4 and not args.ipv6:
        include_ipv6 = False

    if args.ipv6 and not args.ipv4:
        include_ipv4 = False

    connections = collect_connections(
        include_ipv4,
        include_ipv6,
    )

    connections = filter_connections(
        connections,
        args,
    )

    connections = sort_connections(
        connections,
        args.sort,
    )

    return Snapshot(
        timestamp=datetime.now(),
        connections=connections,
    )


def render(
    snapshot: Snapshot,
    args: argparse.Namespace,
) -> None:
    color_enabled = (
        not args.no_color
        and sys.stdout.isatty()
    )

    if not args.no_clear and not args.once:
        print(CLEAR, end="")

    display_header(
        snapshot,
        color_enabled,
        args.interval,
    )

    display_state_summary(
        snapshot.connections,
        color_enabled,
    )

    display_connections(
        snapshot.connections,
        color_enabled,
    )

    display_family_summary(
        snapshot.connections,
    )

    if not args.once:
        print()
        print(
            colorize(
                "Press q to quit or Ctrl-C to stop.",
                DIM,
                color_enabled,
            )
        )

    sys.stdout.flush()


def wait_for_next_refresh(
    terminal: Terminal,
    interval: float,
) -> bool:
    deadline = time.monotonic() + interval

    while True:
        key = terminal.key_pressed()

        if key is not None and key.lower() == "q":
            return False

        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return True

        time.sleep(min(0.05, remaining))


def run_once(args: argparse.Namespace) -> None:
    snapshot = create_snapshot(args)
    render(snapshot, args)


def run_monitor(args: argparse.Namespace) -> None:
    with Terminal() as terminal:
        while True:
            snapshot = create_snapshot(args)
            render(snapshot, args)

            if not wait_for_next_refresh(
                terminal,
                args.interval,
            ):
                break


def main() -> int:
    args = parse_arguments()

    try:
        if args.once:
            run_once(args)
        else:
            run_monitor(args)

    except KeyboardInterrupt:
        print()
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

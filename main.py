import socket
import psutil
import time
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel

console = Console()

# =========================
# SYSTEM INFORMATION
# =========================

def get_system_info():

    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "Unknown"

    return hostname, local_ip


# =========================
# SUSPICIOUS PORT CHECK
# =========================

SUSPICIOUS_PORTS = {
    4444: "Metasploit Default",
    5555: "ADB / Suspicious",
    6666: "Malware Common",
    1337: "Backdoor Port",
    9001: "Tor Related",
}


# =========================
# CONNECTION ANALYSIS
# =========================

def get_connections():

    connections = []

    for conn in psutil.net_connections(kind="inet"):

        try:

            # Skip useless entries
            if conn.status == "NONE":
                continue

            pid = conn.pid

            process_name = "Unknown"

            if pid:
                process_name = psutil.Process(pid).name()

            local_address = "N/A"
            remote_address = "N/A"

            local_port = 0

            if conn.laddr:
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
                local_port = conn.laddr.port

            if conn.raddr:
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"

            suspicious = ""

            if local_port in SUSPICIOUS_PORTS:
                suspicious = SUSPICIOUS_PORTS[local_port]

            connections.append({
                "pid": pid,
                "process": process_name,
                "local": local_address,
                "remote": remote_address,
                "status": conn.status,
                "warning": suspicious
            })

        except:
            pass

    return connections


# =========================
# DISPLAY TABLE
# =========================

def create_table(connections):

    table = Table(title="TCP Connection Viewer Pro")

    table.add_column("PID", style="cyan")
    table.add_column("Process", style="green")
    table.add_column("Local Address", style="yellow")
    table.add_column("Remote Address", style="magenta")
    table.add_column("Status", style="blue")
    table.add_column("Warning", style="red")

    for conn in connections:

        table.add_row(
            str(conn["pid"]),
            conn["process"],
            conn["local"],
            conn["remote"],
            conn["status"],
            conn["warning"]
        )

    return table
# =========================
# MAIN PROGRAM
# =========================

def main():

    hostname, local_ip = get_system_info()

    console.print(
        Panel.fit(
            f"[bold green]Hostname:[/bold green] {hostname}\n"
            f"[bold green]Local IP:[/bold green] {local_ip}",
            title="System Information"
        )
    )

    with Live(refresh_per_second=1, console=console) as live:

        while True:

            connections = get_connections()

            table = create_table(connections)

            live.update(table)

            time.sleep(2)

if __name__ == "__main__":
    main()
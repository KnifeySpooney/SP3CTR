# SP3CTR 0.0.1 - Python Backend (WebSocket Server)
# Spectral Packet Capture & Threat Recognition
# Version: 0.0.4 (TypeError Fix for handler)
# Author: KnifeySpooney
# Inspired by clean, direct code philosophy. "Together, Strong"

# --- Imports ---
import sys
import time
import json  # For sending data as JSON
import asyncio
import websockets  # For WebSocket server functionality
import threading  # To run sniffing in a separate thread
from websockets.server import WebSocketServerProtocol  # For type hinting

try:
    from scapy.all import sniff, get_if_list, get_if_hwaddr, get_if_addr
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.layers.l2 import Ether
except ImportError as e:
    print(f"Error importing Scapy or other necessary modules: {e}")
    print(
        "Please ensure Scapy is installed ('pip install scapy') and you are running this script with appropriate permissions (e.g., sudo on Linux/macOS).")
    sys.exit(1)

# --- Global Variables & Configuration ---
WEBSOCKET_HOST = "localhost"
WEBSOCKET_PORT = 8765
CONNECTED_CLIENTS = set()  # A set to store active WebSocket connections
sniffing_thread: threading.Thread | None = None  # Type hint for clarity
stop_sniffing_event = threading.Event()
current_sniffing_interface: str | None = None  # Type hint

# --- Version ---
__version__ = "0.0.4"


# --- Core Functions ---

def list_network_interfaces_data():
    """
    Lists available network interfaces and returns data suitable for JSON.
    """
    print("Discovering network interfaces for client...")
    interfaces_data = []
    try:
        iface_names = get_if_list()
        for i, iface_name in enumerate(iface_names):
            try:
                hwaddr = get_if_hwaddr(iface_name)
                ipaddr = get_if_addr(iface_name)
                interfaces_data.append({
                    "id": iface_name,
                    "name": f"{iface_name} (MAC: {hwaddr}, IP: {ipaddr})"
                })
            except Exception:
                interfaces_data.append({
                    "id": iface_name,
                    "name": f"{iface_name} (Details N/A)"
                })
        if not interfaces_data:
            print("No usable network interfaces found by Scapy.")
        return interfaces_data
    except Exception as e:
        print(f"Error discovering interfaces: {e}")
        return []


def get_packet_data(packet):
    """
    Extracts packet details into a dictionary for JSON serialization.
    Args:
        packet: A Scapy packet object.
    Returns:
        dict: A dictionary containing packet information.
    """
    packet_time = packet.time if hasattr(packet, 'time') else time.time()
    timestamp = time.strftime("%H:%M:%S", time.localtime(packet_time)) + f".{int((packet_time % 1) * 1000):03d}"

    src_ip, dst_ip = "N/A", "N/A"
    src_port, dst_port = "N/A", "N/A"
    protocol_name = "Unknown"
    length = len(packet)
    info = ""
    flags = ""

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            protocol_name = "TCP"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
            info = f"[{flags}] Seq={tcp_layer.seq} Ack={tcp_layer.ack}"
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            protocol_name = "UDP"
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            if packet.haslayer(DNS) and (udp_layer.dport == 53 or udp_layer.sport == 53):
                protocol_name = "DNS"
                dns_layer = packet.getlayer(DNS)
                q_info = []
                if dns_layer.qdcount > 0 and dns_layer.qd:
                    current_qd = dns_layer.qd
                    for _ in range(dns_layer.qdcount):
                        if current_qd is None: break
                        try:
                            qname = current_qd.qname.decode() if current_qd.qname else "N/A"
                            qtype = current_qd.qtype if hasattr(current_qd, 'qtype') else "N/A"
                            q_info.append(f"Q: {qname} T:{qtype}")
                        except Exception:
                            q_info.append("Query (decode error)")
                        current_qd = current_qd.payload
                if dns_layer.ancount > 0 and dns_layer.an:
                    current_an = dns_layer.an
                    for _ in range(dns_layer.ancount):
                        if current_an is None: break
                        try:
                            rdata = current_an.rdata
                            rname = current_an.rrname.decode() if hasattr(current_an,
                                                                          'rrname') and current_an.rrname else "N/A"
                            if isinstance(rdata, list):
                                rdata_str = ", ".join(str(item) for item in rdata)
                            elif isinstance(rdata, bytes):
                                rdata_str = rdata.decode(errors='ignore')
                            else:
                                rdata_str = str(rdata)
                            q_info.append(f"A: {rname} -> {rdata_str}")
                        except Exception:
                            q_info.append("Answer (decode error)")
                        current_an = current_an.payload

                info = "; ".join(q_info) if q_info else ("Query" if dns_layer.qr == 0 else "Response")

        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
            icmp_layer = packet.getlayer(ICMP)
            type_map = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
            info = f"Type: {icmp_layer.type} ({type_map.get(icmp_layer.type, 'Other')}) Code: {icmp_layer.code}"
        else:
            protocol_name = f"IPProto-{ip_layer.proto}"
            info = "L4 N/A"

    elif packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        src_ip = eth_layer.src
        dst_ip = eth_layer.dst
        protocol_name = f"L2 EtherType-{hex(eth_layer.type)}"
        info = "L2 Traffic"
    else:
        info = "Unknown L2/L3"

    return {
        "timestamp": timestamp,
        "srcIp": str(src_ip),
        "destIp": str(dst_ip),
        "srcPort": str(src_port),
        "destPort": str(dst_port),
        "protocol": protocol_name,
        "length": length,
        "info": info if info else "---"
    }


async def send_to_clients(message_data: dict):
    """Sends a message to all connected WebSocket clients."""
    if CONNECTED_CLIENTS:
        json_message = json.dumps(message_data)
        send_coroutines = [client.send(json_message) for client in CONNECTED_CLIENTS]
        await asyncio.gather(*send_coroutines, return_exceptions=True)


async def packet_sender_callback(packet):
    """
    Callback for Scapy's sniff. Converts packet to JSON and schedules sending via WebSocket.
    """
    try:
        packet_data = get_packet_data(packet)
        asyncio.create_task(send_to_clients({"type": "packet", "data": packet_data}))
    except Exception as e:
        print(f"Error in packet_sender_callback: {e}")


def sniffing_loop(interface_name: str, stop_event: threading.Event, loop: asyncio.AbstractEventLoop):
    """
    The actual sniffing loop that runs in a separate thread.
    Requires the main event loop to be passed for threadsafe operations.
    """
    global current_sniffing_interface
    current_sniffing_interface = interface_name
    print(f"Thread: Starting sniffing on {interface_name}")

    def scapy_callback_wrapper(pkt):
        asyncio.run_coroutine_threadsafe(packet_sender_callback(pkt), loop)

    try:
        sniff(iface=interface_name,
              prn=scapy_callback_wrapper,
              stop_filter=lambda pkt: stop_event.is_set(),
              store=0)
    except PermissionError:
        print(f"Thread: Permission denied to sniff on {interface_name}.")
        asyncio.run_coroutine_threadsafe(
            send_to_clients({"type": "error", "message": "Permission denied to sniff. Try running with sudo/admin."}),
            loop)
    except OSError as e:
        print(f"Thread: OSError on {interface_name}: {e}")
        asyncio.run_coroutine_threadsafe(
            send_to_clients({"type": "error", "message": f"OS Error: {e}. Check interface or Npcap/WinPcap."}), loop)
    except Exception as e:
        print(f"Thread: Unexpected sniffing error: {e}")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "error", "message": f"Sniffing error: {e}"}), loop)
    finally:
        print(f"Thread: Sniffing stopped on {interface_name}")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "status", "message": "Capture stopped."}), loop)
        current_sniffing_interface = None


async def handler(websocket: WebSocketServerProtocol, path: str = None):  # Made path optional
    """
    Handles WebSocket connections and messages from clients.
    """
    global sniffing_thread, stop_sniffing_event, current_sniffing_interface

    main_event_loop = asyncio.get_running_loop()

    CONNECTED_CLIENTS.add(websocket)
    print(f"Client connected: {websocket.remote_address}, Path: {path}")  # Log the path
    try:
        interfaces = list_network_interfaces_data()
        await websocket.send(json.dumps({"type": "interfaces", "data": interfaces}))

        if current_sniffing_interface:
            await websocket.send(
                json.dumps({"type": "status", "message": f"Capture active on {current_sniffing_interface}"}))
        else:
            await websocket.send(json.dumps({"type": "status", "message": "Idle. Select interface and start capture."}))

        async for message in websocket:
            try:
                data = json.loads(message)
                command = data.get("command")

                if command == "get_interfaces":
                    interfaces = list_network_interfaces_data()
                    await websocket.send(json.dumps({"type": "interfaces", "data": interfaces}))

                elif command == "start_capture":
                    if sniffing_thread and sniffing_thread.is_alive():
                        await websocket.send(json.dumps({"type": "error", "message": "Capture is already running."}))
                    else:
                        interface = data.get("interface")
                        if interface:
                            print(f"Received start_capture command for interface: {interface}")
                            stop_sniffing_event.clear()
                            sniffing_thread = threading.Thread(target=sniffing_loop,
                                                               args=(interface, stop_sniffing_event, main_event_loop),
                                                               daemon=True)
                            sniffing_thread.start()
                            await websocket.send(
                                json.dumps({"type": "status", "message": f"Capture started on {interface}"}))
                        else:
                            await websocket.send(
                                json.dumps({"type": "error", "message": "No interface specified for capture."}))

                elif command == "stop_capture":
                    if sniffing_thread and sniffing_thread.is_alive():
                        print("Received stop_capture command.")
                        stop_sniffing_event.set()
                    else:
                        await websocket.send(json.dumps({"type": "status", "message": "Capture not running."}))
            except json.JSONDecodeError:
                print(f"Invalid JSON received: {message}")
                await websocket.send(json.dumps({"type": "error", "message": "Invalid JSON command."}))
            except Exception as e:
                print(f"Error handling message: {e}")
                await websocket.send(json.dumps({"type": "error", "message": f"Server error: {e}"}))

    except websockets.exceptions.ConnectionClosedError:
        print(f"Client disconnected: {websocket.remote_address} (Closed)")
    except Exception as e:
        print(f"Error in WebSocket handler: {e}")
    finally:
        CONNECTED_CLIENTS.remove(websocket)
        print(f"Client connection cleanup: {websocket.remote_address}. Remaining clients: {len(CONNECTED_CLIENTS)}")


async def main_server_loop():
    """
    Main function to start the WebSocket server.
    """
    async with websockets.serve(handler, WEBSOCKET_HOST, WEBSOCKET_PORT) as server:
        print(f"--- SP3CTR {__version__} - WebSocket Server Ready ---")
        print(f"Listening on ws://{WEBSOCKET_HOST}:{WEBSOCKET_PORT}")
        await asyncio.Future()

    # --- Main Execution ---


if __name__ == "__main__":
    try:
        asyncio.run(main_server_loop())
    except KeyboardInterrupt:
        print("\nSP3CTR terminated by user.")
    except Exception as e:
        print(f"Fatal error in main execution: {e}")
    finally:
        print("Shutting down SP3CTR...")
        if sniffing_thread and sniffing_thread.is_alive():
            print("Stopping active capture due to server shutdown...")
            stop_sniffing_event.set()
            sniffing_thread.join(timeout=2)
        print("SP3CTR shutdown complete.")


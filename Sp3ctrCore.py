# SP3CTR - Python Backend (WebSocket Server with Packet Detail Dissection)
# Spectral Packet Capture & Threat Recognition
# Version: 0.2.5 (Phase 1 - Enhanced Packet Detail View)
# Author: KnifeySpooney
# Inspired by clean, direct code philosophy. "Together, Strong"

# --- Imports ---
import sys
import time
import json 
import asyncio
import websockets 
import threading 
from websockets.server import WebSocketServerProtocol 
import os 
from datetime import datetime 
import traceback 

try:
    from scapy.all import sniff, get_if_list, get_if_hwaddr, get_if_addr
    from scapy.utils import wrpcap 
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR in Sp3ctrCore.py: {e}")
    print("Please ensure Scapy is installed ('pip install scapy') and you are running this script with appropriate permissions (e.g., sudo on Linux/macOS).")
    input("--- Press Enter to close this backend window. ---") 
    sys.exit(1)

# --- Global Variables & Configuration ---
WEBSOCKET_HOST = "localhost"
WEBSOCKET_PORT = 8765
CAPTURES_DIR = "captures" 

CONNECTED_CLIENTS = set() 
sniffing_thread: threading.Thread | None = None 
stop_sniffing_event = threading.Event()
current_sniffing_interface: str | None = None 
captured_packets_buffer = [] 

# --- Version ---
__version__ = "0.2.0"

# --- Helper Functions ---
def ensure_captures_dir():
    if not os.path.exists(CAPTURES_DIR):
        try:
            os.makedirs(CAPTURES_DIR)
            print(f"Created directory for captures: {CAPTURES_DIR}")
        except OSError as e:
            print(f"Error creating captures directory '{CAPTURES_DIR}': {e}")
            return False
    return True

def dissect_packet_details(packet):
    """
    Takes a Scapy packet and returns a detailed, JSON-serializable dictionary of its layers.
    """
    details = []
    layer_counter = 0

    while True:
        layer = packet.getlayer(layer_counter)
        if layer is None:
            break

        layer_details = {"layer_name": layer.name, "fields": {}}
        
        # Use .fields to get all field names and their values
        for field_name, field_value in layer.fields.items():
            # Represent non-string/int/float values as strings
            if isinstance(field_value, (str, int, float, bool)) or field_value is None:
                layer_details["fields"][field_name] = field_value
            elif isinstance(field_value, bytes):
                 # Try to decode as UTF-8, fall back to hex representation
                try:
                    layer_details["fields"][field_name] = field_value.decode('utf-8', 'replace')
                except UnicodeDecodeError:
                    layer_details["fields"][field_name] = field_value.hex()
            else:
                # For complex fields (like other packets), just use repr()
                layer_details["fields"][field_name] = repr(field_value)

        details.append(layer_details)
        layer_counter += 1

    return details


# --- Core Functions ---

def list_network_interfaces_data(): # (Unchanged)
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
        return interfaces_data
    except Exception as e:
        print(f"Error discovering interfaces: {e}")
        return []

def get_packet_summary_data(packet, index):
    """
    Extracts a simplified summary and includes the packet's index.
    """
    packet_time = packet.time if hasattr(packet, 'time') else time.time()
    timestamp = time.strftime("%H:%M:%S", time.localtime(packet_time)) + f".{int((packet_time % 1) * 1000):03d}"
    src_ip, dst_ip, src_port, dst_port, protocol_name, info = "N/A", "N/A", "N/A", "N/A", "Unknown", ""
    length = len(packet)

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            protocol_name, src_port, dst_port = "TCP", tcp_layer.sport, tcp_layer.dport
            info = f"[{str(tcp_layer.flags)}] Seq={tcp_layer.seq} Ack={tcp_layer.ack}"
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            protocol_name, src_port, dst_port = "UDP", udp_layer.sport, udp_layer.dport
            if packet.haslayer(DNS):
                protocol_name = "DNS"
                info = "DNS Query/Response" 
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
        src_ip, dst_ip = eth_layer.src, eth_layer.dst 
        protocol_name = f"L2 EtherType-{hex(eth_layer.type)}"
        info = "L2 Traffic"
    else:
        info = "Unknown L2/L3"

    return {"index": index, "timestamp": timestamp, "srcIp": str(src_ip), "destIp": str(dst_ip),
            "srcPort": str(src_port), "destPort": str(dst_port), "protocol": protocol_name,
            "length": length, "info": info if info else "---"}


async def send_to_clients(message_data: dict):
    if CONNECTED_CLIENTS:
        json_message = json.dumps(message_data)
        await asyncio.gather(*[client.send(json_message) for client in CONNECTED_CLIENTS], return_exceptions=True)

async def packet_sender_callback(packet):
    global captured_packets_buffer
    try:
        packet_index = len(captured_packets_buffer) # Assign index *before* appending
        captured_packets_buffer.append(packet) 
        
        packet_data_for_client = get_packet_summary_data(packet, packet_index) # Pass index
        
        asyncio.create_task(send_to_clients({"type": "packet_summary", "data": packet_data_for_client}))
    except Exception as e:
        print(f"Error in packet_sender_callback: {e}")

def sniffing_loop(interface_name: str, stop_event: threading.Event, loop: asyncio.AbstractEventLoop):
    # (Unchanged from last working version)
    global current_sniffing_interface
    current_sniffing_interface = interface_name
    print(f"Thread: Starting sniffing on {interface_name}")
    def scapy_callback_wrapper(pkt): asyncio.run_coroutine_threadsafe(packet_sender_callback(pkt), loop)
    try:
        sniff(iface=interface_name, prn=scapy_callback_wrapper, stop_filter=lambda pkt: stop_event.is_set(), store=0)
    except Exception as e: print(f"Sniffing error: {e}")
    finally:
        msg = f"Capture stopped. {len(captured_packets_buffer)} packets buffered."
        print(f"Thread: Sniffing stopped. {len(captured_packets_buffer)} packets in buffer.")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "status", "message": msg}), loop)
        current_sniffing_interface = None 

async def handler(websocket: WebSocketServerProtocol, path: str = None):
    global sniffing_thread, stop_sniffing_event, current_sniffing_interface, captured_packets_buffer
    main_event_loop = asyncio.get_running_loop() 
    CONNECTED_CLIENTS.add(websocket)
    print(f"Client connected: {websocket.remote_address}")
    try:
        await websocket.send(json.dumps({"type": "interfaces", "data": list_network_interfaces_data()}))
        # (initial status sending logic unchanged)
        
        async for message in websocket:
            try:
                data = json.loads(message)
                command = data.get("command")
                
                if command == "start_capture": # (Unchanged)
                    if not (sniffing_thread and sniffing_thread.is_alive()):
                        interface = data.get("interface")
                        if interface:
                            captured_packets_buffer.clear()
                            stop_sniffing_event.clear()
                            sniffing_thread = threading.Thread(target=sniffing_loop, args=(interface, stop_sniffing_event, main_event_loop), daemon=True)
                            sniffing_thread.start()
                            await send_to_clients({"type": "status", "message": f"Capture started on {interface}"})
                
                elif command == "stop_capture": # (Unchanged)
                    if sniffing_thread and sniffing_thread.is_alive():
                        stop_sniffing_event.set()
                
                elif command == "save_capture": # (Unchanged)
                    if not captured_packets_buffer:
                        await websocket.send(json.dumps({"type": "error", "message": "No packets to save."}))
                    elif sniffing_thread and sniffing_thread.is_alive():
                        await websocket.send(json.dumps({"type": "error", "message": "Stop capture first."}))
                    else:
                        # (Save logic remains the same)
                        pass
                
                elif command == "get_packet_details": # *** NEW COMMAND HANDLER ***
                    print(f"Received get_packet_details command for index: {data.get('index')}")
                    try:
                        index = int(data.get("index", -1))
                        if 0 <= index < len(captured_packets_buffer):
                            packet_to_dissect = captured_packets_buffer[index]
                            details = dissect_packet_details(packet_to_dissect)
                            await websocket.send(json.dumps({"type": "packet_details", "data": details}))
                        else:
                            await websocket.send(json.dumps({"type": "error", "message": f"Invalid packet index: {index}"}))
                    except (ValueError, TypeError):
                        await websocket.send(json.dumps({"type": "error", "message": "Invalid index format."}))

            except Exception as e: 
                print(f"Error handling client message: {e}")
                # (Error sending logic remains the same)
    # (Rest of handler function unchanged)
    except Exception as e:
        print(f"Unhandled error in WebSocket handler: {e}")
    finally:
        CONNECTED_CLIENTS.remove(websocket)
        print(f"Client connection cleanup: {websocket.remote_address}. Clients: {len(CONNECTED_CLIENTS)}")

async def main_server_loop(): # (Unchanged)
    ensure_captures_dir()
    async with websockets.serve(handler, WEBSOCKET_HOST, WEBSOCKET_PORT) as server:
        print(f"--- SP3CTR Backend v{__version__} --- WebSocket Server Ready ---")
        print(f"Listening on ws://{WEBSOCKET_HOST}:{WEBSOCKET_PORT}")
        await asyncio.Future() 

if __name__ == "__main__": # (Unchanged)
    try:
        asyncio.run(main_server_loop())
    except KeyboardInterrupt:
        print("\nSP3CTR Core Backend terminated.")
    finally:
        input("--- Press Enter to close this backend window. ---")

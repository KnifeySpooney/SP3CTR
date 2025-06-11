# SP3CTR - Python Backend
# Spectral Packet Capture & Threat Recognition
# Version: 0.3.1 - Galiano (Patched - No Filtering)
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
    from scapy.all import sniff, get_if_list, get_if_hwaddr, get_if_addr, rdpcap
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
__version__ = "0.3.1"

# --- Helper & Core Functions ---
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
    details = []
    layer_counter = 0
    while True:
        layer = packet.getlayer(layer_counter)
        if layer is None: break
        layer_details = {"layer_name": layer.name, "fields": {}}
        for field_name, field_value in layer.fields.items():
            try:
                if isinstance(field_value, (str, int, float, bool)) or field_value is None:
                    layer_details["fields"][field_name] = field_value
                elif isinstance(field_value, bytes):
                    layer_details["fields"][field_name] = field_value.decode('utf-8', 'replace')
                else:
                    layer_details["fields"][field_name] = repr(field_value)
            except Exception:
                layer_details["fields"][field_name] = "Could not represent field"
        details.append(layer_details)
        layer_counter += 1
    return details

def get_pcap_list():
    print("Scanning for PCAP files...")
    if not os.path.isdir(CAPTURES_DIR): return []
    try:
        files = [f for f in os.listdir(CAPTURES_DIR) if f.lower().endswith(('.pcap', '.pcapng'))]
        print(f"Found {len(files)} PCAP files.")
        return sorted(files, key=lambda f: os.path.getmtime(os.path.join(CAPTURES_DIR, f)), reverse=True)
    except Exception as e:
        print(f"Error reading captures directory: {e}")
        return []

def list_network_interfaces_data():
    print("Scanning for network interfaces...")
    interfaces_data = []
    iface_names = get_if_list()
    for i, iface_name in enumerate(iface_names):
        try:
            hwaddr = get_if_hwaddr(iface_name)
            ipaddr = get_if_addr(iface_name)
            interfaces_data.append({"id": iface_name, "name": f"{iface_name} (MAC: {hwaddr}, IP: {ipaddr})"})
        except Exception:
            interfaces_data.append({"id": iface_name, "name": f"{iface_name} (Details N/A)"})
    return interfaces_data

def get_packet_summary_data(packet, index):
    """
    Extracts a simplified summary and includes the packet's index.
    *** FIXED: Handles EDecimal timestamps from PCAP files. ***
    """
    packet_time = packet.time if hasattr(packet, 'time') else time.time()
    
    # *** FIX IS HERE: Explicitly cast packet_time to a float ***
    # This handles the EDecimal object correctly.
    try:
        ts = float(packet_time)
        timestamp = time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}"
    except (TypeError, ValueError):
        # Fallback if timestamp is somehow invalid
        timestamp = time.strftime("%H:%M:%S")

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
            info = f"Type: {icmp_layer.type} ({type_map.get(icmp_layer.type, 'Other')})"
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
        packet_index = len(captured_packets_buffer) 
        captured_packets_buffer.append(packet) 
        packet_data_for_client = get_packet_summary_data(packet, packet_index)
        asyncio.create_task(send_to_clients({"type": "packet_summary", "data": packet_data_for_client}))
    except Exception as e: print(f"Error in packet_sender_callback: {e}")

def sniffing_loop(interface_name: str, stop_event: threading.Event, loop: asyncio.AbstractEventLoop):
    global current_sniffing_interface
    current_sniffing_interface = interface_name
    print(f"Thread: Starting sniffing on {interface_name}")
    def scapy_callback_wrapper(pkt): asyncio.run_coroutine_threadsafe(packet_sender_callback(pkt), loop)
    try:
        sniff(iface=interface_name, prn=scapy_callback_wrapper, stop_filter=lambda pkt: stop_event.is_set(), store=0)
    except Exception as e:
        msg = f"Sniffing error on {interface_name}: {e}"
        print(f"Thread: {msg}")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "error", "message": msg}), loop)
    finally:
        msg = f"Capture stopped. {len(captured_packets_buffer)} packets buffered."
        print(f"Thread: Sniffing stopped. {len(captured_packets_buffer)} packets in buffer.")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "status", "message": msg}), loop)
        current_sniffing_interface = None 

async def load_and_stream_pcap(filename: str):
    global captured_packets_buffer
    if ".." in filename or os.path.isabs(filename):
        await send_to_clients({"type": "error", "message": "Invalid filename."}); return
    filepath = os.path.join(CAPTURES_DIR, filename)
    if not os.path.exists(filepath):
        await send_to_clients({"type": "error", "message": f"File not found: {filename}"}); return
    await send_to_clients({"type": "status", "message": f"Loading {filename}..."})
    try:
        packets_from_file = rdpcap(filepath)
        captured_packets_buffer.clear()
        print(f"Streaming {len(packets_from_file)} packets from {filename}...")
        for i, packet in enumerate(packets_from_file):
            captured_packets_buffer.append(packet)
            packet_summary = get_packet_summary_data(packet, i)
            await send_to_clients({"type": "packet_summary", "data": packet_summary})
            if (i + 1) % 100 == 0: await asyncio.sleep(0.01)
        final_status_msg = f"Finished loading {filename}. {len(packets_from_file)} packets loaded."
        print(final_status_msg)
        await send_to_clients({"type": "status", "message": final_status_msg})
    except Exception as e:
        error_msg = f"Failed to load or process {filename}: {e}"
        print(error_msg)
        await send_to_clients({"type": "error", "message": error_msg})

async def handler(websocket: WebSocketServerProtocol):
    global sniffing_thread, stop_sniffing_event, captured_packets_buffer
    main_event_loop = asyncio.get_running_loop() 
    CONNECTED_CLIENTS.add(websocket)
    print(f"Client connected: {websocket.remote_address}")
    try:
        # *** ROBUST INITIALIZATION BLOCK ***
        try:
            print("Attempting to get and send interface list...")
            interfaces = list_network_interfaces_data()
            await websocket.send(json.dumps({"type": "interfaces", "data": interfaces}))
            print("Successfully sent interface list.")
        except Exception as e:
            print(f"!!! CRITICAL ERROR during initial interface list: {e}")
            traceback.print_exc()
            await websocket.send(json.dumps({"type": "error", "message": "Failed to get network interfaces from server. Run as Admin/sudo?"}))
        
        async for message in websocket:
            try:
                data = json.loads(message)
                command = data.get("command")
                if command == "start_capture":
                    if not (sniffing_thread and sniffing_thread.is_alive()):
                        interface = data.get("interface")
                        if interface:
                            captured_packets_buffer.clear()
                            stop_sniffing_event.clear()
                            sniffing_thread = threading.Thread(target=sniffing_loop, args=(interface, stop_sniffing_event, main_event_loop), daemon=True)
                            sniffing_thread.start()
                            await send_to_clients({"type": "status", "message": f"Capture started on {interface}"})
                elif command == "stop_capture":
                    if sniffing_thread and sniffing_thread.is_alive():
                        stop_sniffing_event.set()
                elif command == "save_capture":
                    if captured_packets_buffer and not (sniffing_thread and sniffing_thread.is_alive()):
                        if ensure_captures_dir():
                            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                            fname = os.path.join(CAPTURES_DIR, f"sp3ctr_capture_{ts}.pcap")
                            wrpcap(fname, captured_packets_buffer)
                            await websocket.send(json.dumps({"type": "status", "message": f"Saved: {os.path.basename(fname)}"}))
                elif command == "get_packet_details":
                    index = int(data.get("index", -1))
                    if 0 <= index < len(captured_packets_buffer):
                        details = dissect_packet_details(captured_packets_buffer[index])
                        await websocket.send(json.dumps({"type": "packet_details", "data": details}))
                elif command == "get_pcap_list":
                    pcap_files = get_pcap_list()
                    await websocket.send(json.dumps({"type": "pcap_list", "data": pcap_files}))
                elif command == "load_pcap_file":
                    filename = data.get("filename")
                    if not (sniffing_thread and sniffing_thread.is_alive()) and filename:
                        asyncio.create_task(load_and_stream_pcap(filename))
            except Exception as e: print(f"Error handling message: {e}")
    except Exception as e: print(f"Error in WebSocket connection handler: {e}")
    finally:
        CONNECTED_CLIENTS.remove(websocket)
        print(f"Client connection cleanup: {websocket.remote_address}. Clients: {len(CONNECTED_CLIENTS)}")

async def main_server_loop():
    ensure_captures_dir()
    async with websockets.serve(handler, WEBSOCKET_HOST, WEBSOCKET_PORT) as server:
        print(f"--- SP3CTR Backend v{__version__} --- WebSocket Server Ready ---")
        print(f"Listening on ws://{WEBSOCKET_HOST}:{WEBSOCKET_PORT}")
        await asyncio.Future() 

if __name__ == "__main__":
    try:
        asyncio.run(main_server_loop())
    except KeyboardInterrupt: print("\nSP3CTR Core Backend terminated.")
    finally:
        if sniffing_thread and sniffing_thread.is_alive():
            print("Stopping active capture...")
            stop_sniffing_event.set()
            sniffing_thread.join(timeout=2)
        print("Shutdown complete.")
        input("--- Press Enter to close this backend window. ---")


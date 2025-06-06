# SP3CTR 0.2.1 "Quadra"- Python Backend (WebSocket Server with Save Capture & w/ Persistent Window)
# Spectral Packet Capture & Threat Recognition
# Version: 0.2.1 (Packet Send Logging)
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
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR in Sp3ctrCore.py: {e}")
    print("This usually means a required library (like Scapy or websockets) is not installed correctly.")
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
__version__ = "0.2.1" # Updated version

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

# --- Core Functions ---

def list_network_interfaces_data():
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

def get_packet_data(packet): # (Content largely unchanged, assumed to be working)
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
            if packet.haslayer(DNS) and (udp_layer.dport == 53 or udp_layer.sport == 53):
                protocol_name = "DNS"
                dns_layer = packet.getlayer(DNS)
                info = "DNS Query/Response" # Simplified from previous detailed for brevity
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

    return {"timestamp": timestamp, "srcIp": str(src_ip), "destIp": str(dst_ip),
            "srcPort": str(src_port), "destPort": str(dst_port), "protocol": protocol_name,
            "length": length, "info": info if info else "---"}


async def send_to_clients(message_data: dict):
    if CONNECTED_CLIENTS:
        json_message = json.dumps(message_data)
        await asyncio.gather(*[client.send(json_message) for client in CONNECTED_CLIENTS], return_exceptions=True)

async def packet_sender_callback(packet):
    global captured_packets_buffer
    try:
        # *** ADDED LOG HERE ***
        print(f"Backend: packet_sender_callback triggered for packet: {packet.summary()[:100]}...") # Log summary of packet

        captured_packets_buffer.append(packet) 
        packet_data_for_client = get_packet_data(packet)
        
        # *** ADDED LOG HERE ***
        print(f"Backend: Attempting to send packet data to clients: {json.dumps(packet_data_for_client)[:150]}...")
        
        asyncio.create_task(send_to_clients({"type": "packet", "data": packet_data_for_client}))
    except Exception as e:
        print(f"Error in packet_sender_callback: {e}")

def sniffing_loop(interface_name: str, stop_event: threading.Event, loop: asyncio.AbstractEventLoop):
    global current_sniffing_interface, captured_packets_buffer
    current_sniffing_interface = interface_name
    print(f"Thread: Starting sniffing on {interface_name}")
    
    def scapy_callback_wrapper(pkt):
        asyncio.run_coroutine_threadsafe(packet_sender_callback(pkt), loop)

    try:
        sniff(iface=interface_name, prn=scapy_callback_wrapper,
              stop_filter=lambda pkt: stop_event.is_set(), store=0)
    # ... (rest of sniffing_loop unchanged from v0.1.1) ...
    except PermissionError:
        msg = "Permission denied to sniff. Try running with sudo/admin."
        print(f"Thread: {msg}")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "error", "message": msg}), loop)
    except OSError as e:
        msg = f"OS Error: {e}. Check interface or Npcap/WinPcap."
        print(f"Thread: {msg}")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "error", "message": msg}), loop)
    except Exception as e:
        msg = f"Sniffing error: {e}"
        print(f"Thread: Unexpected {msg.lower()}")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "error", "message": msg}), loop)
    finally:
        msg = f"Capture stopped. {len(captured_packets_buffer)} packets buffered."
        print(f"Thread: Sniffing stopped on {interface_name}. {len(captured_packets_buffer)} packets in buffer.")
        asyncio.run_coroutine_threadsafe(send_to_clients({"type": "status", "message": msg}), loop)
        current_sniffing_interface = None 


async def handler(websocket: WebSocketServerProtocol, path: str = None): # (Unchanged from v0.1.1)
    global sniffing_thread, stop_sniffing_event, current_sniffing_interface, captured_packets_buffer
    main_event_loop = asyncio.get_running_loop() 
    CONNECTED_CLIENTS.add(websocket)
    print(f"Client connected: {websocket.remote_address}, Path: {path}")
    try:
        await websocket.send(json.dumps({"type": "interfaces", "data": list_network_interfaces_data()}))
        status_msg = "Idle. Select interface and start capture."
        if current_sniffing_interface:
             status_msg = f"Capture active on {current_sniffing_interface}. {len(captured_packets_buffer)} pkts."
        elif captured_packets_buffer:
            status_msg = f"Capture stopped. {len(captured_packets_buffer)} pkts. Ready to save."
        await websocket.send(json.dumps({"type": "status", "message": status_msg}))

        async for message in websocket:
            try:
                data = json.loads(message)
                command = data.get("command")
                
                if command == "start_capture":
                    if sniffing_thread and sniffing_thread.is_alive():
                        await websocket.send(json.dumps({"type": "error", "message": "Capture running."}))
                    else:
                        interface = data.get("interface")
                        if interface:
                            captured_packets_buffer.clear()
                            stop_sniffing_event.clear()
                            sniffing_thread = threading.Thread(target=sniffing_loop, args=(interface, stop_sniffing_event, main_event_loop), daemon=True)
                            sniffing_thread.start()
                            await send_to_clients({"type": "status", "message": f"Capture started on {interface}"})
                        else:
                            await websocket.send(json.dumps({"type": "error", "message": "No interface."}))
                elif command == "stop_capture":
                    if sniffing_thread and sniffing_thread.is_alive():
                        stop_sniffing_event.set()
                    else:
                        await websocket.send(json.dumps({"type": "status", "message": "Capture not running."}))
                elif command == "save_capture":
                    if not captured_packets_buffer:
                        await websocket.send(json.dumps({"type": "error", "message": "No packets to save."}))
                    elif sniffing_thread and sniffing_thread.is_alive():
                        await websocket.send(json.dumps({"type": "error", "message": "Stop capture first."}))
                    else:
                        if ensure_captures_dir():
                            fname = os.path.join(CAPTURES_DIR, f"sp3ctr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
                            try:
                                wrpcap(fname, captured_packets_buffer)
                                await websocket.send(json.dumps({"type": "status", "message": f"Saved: {os.path.basename(fname)}"}))
                            except Exception as e:
                                await websocket.send(json.dumps({"type": "error", "message": f"Save failed: {e}"}))
                        else:
                             await websocket.send(json.dumps({"type": "error", "message": "Server dir error."}))
            except Exception as e: 
                print(f"Error handling client message: {e}")
                try: 
                    await websocket.send(json.dumps({"type": "error", "message": f"Server processing error."}))
                except: pass 
    except websockets.exceptions.ConnectionClosed: 
        print(f"Client {websocket.remote_address} disconnected (closed).")
    except websockets.exceptions.ConnectionClosedError:
        print(f"Client {websocket.remote_address} disconnected (error).")
    except Exception as e:
        print(f"Unhandled error in WebSocket handler: {e}")
    finally:
        CONNECTED_CLIENTS.remove(websocket)
        print(f"Client connection cleanup: {websocket.remote_address}. Clients: {len(CONNECTED_CLIENTS)}")

async def main_server_loop(): # (Unchanged from v0.1.1)
    ensure_captures_dir()
    async with websockets.serve(handler, WEBSOCKET_HOST, WEBSOCKET_PORT) as server:
        print(f"--- SP3CTR Backend v{__version__} --- WebSocket Server Ready ---")
        print(f"Listening on ws://{WEBSOCKET_HOST}:{WEBSOCKET_PORT}")
        print(f"PCAP files saved in: '{os.path.abspath(CAPTURES_DIR)}'")
        await asyncio.Future() 

# --- Main Execution (Unchanged from v0.1.1 - includes persistent window logic) ---
if __name__ == "__main__":
    try:
        print(f"--- SP3CTR Core Backend v{__version__} Attempting to Start ---")
        asyncio.run(main_server_loop())
    except KeyboardInterrupt:
        print("\nSP3CTR Core Backend (WebSocket Server) terminated by user (Ctrl+C).")
    except SystemExit as e: 
        print(f"SP3CTR Core Backend exiting with code: {e.code}")
    except ImportError: 
        pass 
    except Exception as e:
        print(f"!!! FATAL ERROR in SP3CTR Core Backend (WebSocket Server) execution !!!")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {e}")
        print("Traceback (most recent call last):")
        traceback.print_exc() 
    finally:
        print("\n--- SP3CTR Core Backend (WebSocket Server) window will pause before closing. ---")
        print("--- Review any messages above for errors. ---")
        if sniffing_thread and sniffing_thread.is_alive():
            print("Attempting to stop active sniffing thread due to shutdown...")
            stop_sniffing_event.set()
            sniffing_thread.join(timeout=3) 
            if sniffing_thread.is_alive():
                print("Warning: Sniffing thread did not terminate cleanly.")
        input("--- Press Enter to close this backend window. ---")

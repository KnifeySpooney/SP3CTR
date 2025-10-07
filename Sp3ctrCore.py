# SP3CTR - Python Backend
# Spectral Packet Capture & Threat Recognition
# Version: 0.9.2 (Conversation Storytelling)
# Author: KnifeySpooney
# "Together, Strong"

# --- Imports ---
import sys
import os
import platform
import time
import json 
import asyncio
import websockets 
import threading 
from websockets.server import WebSocketServerProtocol 
from datetime import datetime, timezone
import traceback 
import sqlite3
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import ctypes # For displaying Windows message boxes

# --- LOGGING SETUP ---
# Determine where to put the log file based on whether we are bundled or not
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

log_file = os.path.join(application_path, 'sp3ctr_backend.log')

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s')
log_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)
logger = logging.getLogger('sp3ctr_logger')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)
logger.addHandler(console_handler)

# --- Scapy Imports ---
try:
    from scapy.all import sniff, conf, get_if_addr
    from scapy.utils import wrpcap 
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
except ImportError as e:
    logger.critical(f"CRITICAL IMPORT ERROR: {e}\nPlease ensure Scapy is installed.")
    sys.exit(1)

# --- Helper Functions for Executable Compatibility ---
def resolve_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def show_critical_error_and_exit(title, message):
    logger.critical(f"{title}: {message}")
    if platform.system() == "Windows":
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
    sys.exit(1)

# --- Configuration ---
WEBSOCKET_HOST = "localhost"
WEBSOCKET_PORT = 8765
__version__ = "0.9.2"
VANGUARD_DB = resolve_path("vanguard.db")
UI_FILE = resolve_path("sp3ctrUI.html") 
KNOWN_DB_HASH = "2a0236de9ff00923fdbb99ea0dba6cb1eec820e4fcd625c674f5e1287cb314e9"
APP_DATA_PATH = os.path.join(os.getenv('APPDATA'), 'SP3CTR') if platform.system() == "Windows" else os.path.expanduser("~/.sp3ctr")
LOCAL_INTEL_DB = os.path.join(APP_DATA_PATH, "local_intel.db")
CAPTURES_DIR = os.path.join(APP_DATA_PATH, "captures")
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 30

# --- Runtime State ---
CONNECTED_CLIENTS = set() 
sniffing_thread: threading.Thread | None = None 
stop_sniffing_event = threading.Event()
captured_packets_buffer = [] 
scan_tracker = {}
alerted_scanners = set()
bandwidth_aggregator = {} 
bandwidth_task: asyncio.Task | None = None 
conversation_tracker = {}

# --- Prerequisite & Integrity Checks ---
def check_windows_prerequisites():
    if platform.system() != "Windows": return True
    try:
        if not conf.ifaces or len(conf.ifaces) == 0:
             raise OSError("No network interfaces found. Npcap may not be installed or running correctly.")
    except Exception as e:
        show_critical_error_and_exit("SP3CTR - Prerequisite Check Failed", "Npcap driver not found or failed to load!\n\nSP3CTR requires Npcap to capture network traffic on Windows. Please download and install it from https://npcap.com/#download")
    logger.info("Npcap driver check passed.")
    return True

def verify_db_integrity():
    if not os.path.exists(VANGUARD_DB): show_critical_error_and_exit( "SP3CTR - Integrity Check Failed", f"Vanguard database '{os.path.basename(VANGUARD_DB)}' is missing.")
    sha256_hash = hashlib.sha256()
    try:
        with open(VANGUARD_DB, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
        current_hash = sha256_hash.hexdigest()
        if current_hash == KNOWN_DB_HASH:
            logger.info("Vanguard database integrity verified successfully.")
            return True
        else:
            show_critical_error_and_exit("SP3CTR - Integrity Check Failed", f"Vanguard database hash mismatch. Expected: {KNOWN_DB_HASH}, Got: {current_hash}")
            return False
    except Exception as e:
        show_critical_error_and_exit("SP3CTR - Integrity Check Failed", f"An error occurred during hash verification: {e}")
        return False

def ensure_app_dirs():
    try:
        if not os.path.exists(APP_DATA_PATH): os.makedirs(APP_DATA_PATH); logger.info(f"Created AppData directory: {APP_DATA_PATH}")
        if not os.path.exists(CAPTURES_DIR): os.makedirs(CAPTURES_DIR); logger.info(f"Created Captures directory: {CAPTURES_DIR}")
    except OSError as e:
        show_critical_error_and_exit("SP3CTR - Directory Creation Failed", f"Could not create necessary application directories in {APP_DATA_PATH}.\n\nError: {e}")

# --- Database Functions ---
def initialize_local_intel_db():
    try:
        con = sqlite3.connect(LOCAL_INTEL_DB)
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS scan_history (scanner_ip TEXT PRIMARY KEY, scan_count INTEGER NOT NULL, last_seen TEXT NOT NULL)")
        con.commit(); con.close(); logger.info(f"Local intelligence database '{LOCAL_INTEL_DB}' is ready.")
    except sqlite3.Error as e:
        show_critical_error_and_exit("SP3CTR - Local Database Error", f"Failed to create or open local_intel.db.\n\nError: {e}")

def get_top_scanners_from_db():
    try:
        con = sqlite3.connect(LOCAL_INTEL_DB, check_same_thread=False); cur = con.cursor()
        res = cur.execute("SELECT scanner_ip, scan_count FROM scan_history ORDER BY scan_count DESC LIMIT 5")
        top_scanners = [{"ip": row[0], "count": row[1]} for row in res.fetchall()]; con.close()
        return top_scanners
    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve top scanners: {e}", exc_info=True); return []

def update_scan_history(scanner_ip: str) -> int:
    try:
        con = sqlite3.connect(LOCAL_INTEL_DB, check_same_thread=False); cur = con.cursor()
        now_utc = datetime.now(timezone.utc).isoformat()
        cur.execute("INSERT INTO scan_history (scanner_ip, scan_count, last_seen) VALUES (?, 1, ?) ON CONFLICT(scanner_ip) DO UPDATE SET scan_count = scan_count + 1, last_seen = excluded.last_seen", (scanner_ip, now_utc))
        con.commit()
        res = cur.execute("SELECT scan_count FROM scan_history WHERE scanner_ip = ?", (scanner_ip,)); count_data = res.fetchone(); con.close()
        history_count = count_data[0] if count_data else 1
        logger.warning(f"PORT SCAN LOGGED: IP {scanner_ip} has now been recorded scanning {history_count} time(s).")
        return history_count
    except sqlite3.Error as e:
        logger.error(f"Failed to update scan history for {scanner_ip}: {e}", exc_info=True); return 1

# --- Threat Detection, Heuristics & Storytelling ---
def vanguard_heuristic_analysis(packet):
    tags = set()
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        sport, dport = packet.sport, packet.dport
        if 80 in (sport, dport) or 443 in (sport, dport): tags.add("Web Browsing")
        if 53 in (sport, dport): tags.add("DNS")
        if any(p in (sport, dport) for p in [25, 110, 143, 465, 587, 993, 995]): tags.add("Email")
        if 20 in (sport, dport) or 21 in (sport, dport): tags.add("FTP")
        if 22 in (sport, dport): tags.add("SSH")
        if 27015 <= sport <= 27030 or 27015 <= dport <= 27030: tags.add("Gaming")
        if 3074 in (sport, dport): tags.add("Gaming")
    if packet.haslayer(DNS) and len(packet[DNS]) > 512: tags.add("Large DNS Payload")
    if (packet.haslayer(TCP) or packet.haslayer(UDP)) and (packet.sport > 49151 or packet.dport > 49151): tags.add("High Port")
    return list(tags)

async def check_for_port_scan(packet, loop):
    if not (TCP in packet and packet[TCP].flags == 'S' and IP in packet): return
    src_ip, dst_ip, dport = packet[IP].src, packet[IP].dst, packet[TCP].dport
    current_time = time.time()
    scan_tracker.setdefault(src_ip, {}).setdefault(dst_ip, {"ports": set(), "timestamps": []})
    target_info = scan_tracker[src_ip][dst_ip]
    target_info["ports"].add(dport)
    target_info["timestamps"] = [ts for ts in target_info["timestamps"] if current_time - ts <= PORT_SCAN_WINDOW]
    if len(target_info["ports"]) >= PORT_SCAN_THRESHOLD and (src_ip, dst_ip) not in alerted_scanners:
        alerted_scanners.add((src_ip, dst_ip))
        logger.warning(f"PORT SCAN DETECTED from {src_ip} targeting {dst_ip} on {len(target_info['ports'])} ports.")
        history_count = update_scan_history(src_ip)
        alert_data = {"type": "scan_alert", "data": {"scanner": src_ip, "target": dst_ip, "port_count": len(target_info["ports"]), "history_count": history_count}}
        asyncio.run_coroutine_threadsafe(send_to_clients(alert_data), loop)

def get_canonical_conversation_key(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        proto = "TCP" if TCP in packet else "UDP"
        ip1, ip2 = sorted((packet[IP].src, packet[IP].dst))
        port1 = packet[proto].sport if ip1 == packet[IP].src else packet[proto].dport
        port2 = packet[proto].dport if ip1 == packet[IP].src else packet[proto].sport
        return (proto, ip1, port1, ip2, port2)
    return None

def update_conversation_tracker(packet, key):
    state = conversation_tracker.setdefault(key, {"steps": set()})
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 0 and DNSQR in packet:
        state["dns_query"] = packet[DNSQR].qname.decode('utf-8', 'ignore')
    elif DNS in packet and packet[DNS].qr == 1 and DNSRR in packet:
        for i in range(packet[DNS].ancount):
            if packet[DNSRR][i].type == 1: # A record
                state["dns_response"] = packet[DNSRR][i].rdata
                state["steps"].add("dns_resolution")
    elif TCP in packet:
        flags = packet[TCP].flags
        if flags == 'S': state["steps"].add("tcp_syn")
        elif flags == 'SA': state["steps"].add("tcp_syn_ack")
        elif flags == 'A' and "tcp_syn_ack" in state["steps"]: state["steps"].add("tcp_ack_of_syn")
        if Raw in packet:
            payload = packet[Raw].load
            if b"GET " in payload or b"POST " in payload:
                state["steps"].add("http_request")

def generate_conversation_story(state):
    story_parts = []
    if "dns_query" in state:
        part = f"A DNS query was made for '{state['dns_query']}'"
        if "dns_response" in state: part += f", resolving to {state['dns_response']}."
        else: part += ", but a response has not been seen."
        story_parts.append(part)
    
    if "tcp_syn" in state and "tcp_syn_ack" in state and "tcp_ack_of_syn" in state:
        story_parts.append("A three-way TCP handshake successfully established a connection.")
    elif "tcp_syn" in state:
        story_parts.append("A TCP connection was initiated (SYN sent).")
        
    if "http_request" in state:
        story_parts.append("An unencrypted HTTP web request was sent to the server.")
    
    return "\n".join(story_parts) or "No clear narrative could be generated for this conversation yet."

# --- Core Packet Processing & Dissection ---
def get_conversation_id(packet):
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        if TCP in packet: return f"{src_ip}:{packet[TCP].sport} → {dst_ip}:{packet[TCP].dport}"
        elif UDP in packet: return f"{src_ip}:{packet[UDP].sport} → {dst_ip}:{packet[UDP].dport}"
        else: return f"{src_ip} → {dst_ip}"
    elif Ether in packet: return f"{packet[Ether].src} → {packet[Ether].dst}"
    return None

def dissect_packet_details(packet):
    details, layer_counter = [], 0
    while (layer := packet.getlayer(layer_counter)) is not None:
        layer_details = {"layer_name": layer.name, "fields": {}}
        for field_name, field_value in layer.fields.items():
            if isinstance(field_value, (str, int, float, bool)) or field_value is None: layer_details["fields"][field_name] = field_value
            elif isinstance(field_value, bytes): layer_details["fields"][field_name] = field_value.decode('utf-8', 'replace')
            else: layer_details["fields"][field_name] = repr(field_value)
        details.append(layer_details); layer_counter += 1
    return details

def get_threat_info(ip_address: str):
    try:
        con = sqlite3.connect(VANGUARD_DB, check_same_thread=False); cur = con.cursor()
        res = cur.execute("SELECT threat_type, confidence, source, notes FROM threats WHERE ip_address = ?", (ip_address,)); threat_data = res.fetchone(); con.close()
        if threat_data: return {"type": threat_data[0], "confidence": threat_data[1], "source": threat_data[2], "notes": threat_data[3]}
        return None
    except Exception as e:
        logger.error(f"Vanguard DB query error for IP '{ip_address}': {e}", exc_info=True); return None

def get_packet_summary_data(packet, index):
    packet_time = packet.time
    timestamp = time.strftime("%H:%M:%S", time.localtime(packet_time)) + f".{int((packet_time % 1) * 1000):03d}"
    src_ip, dst_ip, src_port, dst_port, protocol_name, info, threat_info = "N/A", "N/A", "N/A", "N/A", "Unknown", "", None
    length = len(packet)
    tags = vanguard_heuristic_analysis(packet)
    if IP in packet:
        ip_layer = packet[IP]; src_ip, dst_ip = ip_layer.src, ip_layer.dst
        if (src_threat := get_threat_info(src_ip)): threat_info = {"ip": src_ip, **src_threat}
        elif (dst_threat := get_threat_info(dst_ip)): threat_info = {"ip": dst_ip, **dst_threat}
        if TCP in packet: tcp = packet[TCP]; protocol_name, src_port, dst_port = "TCP", tcp.sport, tcp.dport; info = f"Flags: {tcp.flags}"
        elif UDP in packet: udp = packet[UDP]; protocol_name, src_port, dst_port = "UDP", udp.sport, udp.dport
        elif ICMP in packet: protocol_name = "ICMP"; info = f"Type: {packet[ICMP].type}"
        else: protocol_name = f"IPProto-{ip_layer.proto}"
    elif Ether in packet: eth = packet[Ether]; src_ip, dst_ip = eth.src, eth.dst; protocol_name = "L2"; info = f"EtherType: {hex(eth.type)}"
    return {"index": index, "timestamp": timestamp, "srcIp": str(src_ip), "destIp": str(dst_ip), "srcPort": str(src_port), "destPort": str(dst_port), "protocol": protocol_name, "length": length, "info": info or "---", "threatInfo": threat_info, "tags": tags}

def list_network_interfaces_data():
    return [{"id": iface_id, "name": iface_obj.name or iface_obj.description, "ip": get_if_addr(iface_id) or "N/A"} for iface_id, iface_obj in conf.ifaces.items()]

# --- WebSocket & Sniffing Loop ---
async def send_to_clients(message_data: dict):
    if CONNECTED_CLIENTS: await asyncio.gather(*[client.send(json.dumps(message_data)) for client in CONNECTED_CLIENTS], return_exceptions=True)

async def bandwidth_calculator_loop():
    global bandwidth_aggregator
    logger.info("Bandwidth calculator task started.")
    while not stop_sniffing_event.is_set():
        await asyncio.sleep(1)
        if not sniffing_thread or not sniffing_thread.is_alive(): continue
        current_data = bandwidth_aggregator; bandwidth_aggregator = {}
        if not current_data: continue
        kbps_data = {conv: (byte_count / 1024) for conv, byte_count in current_data.items()}
        top_5 = sorted(kbps_data.items(), key=lambda item: item[1], reverse=True)[:5]
        payload = {"timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), "top_conversations": [{"id": conv, "kbps": round(kbps, 2)} for conv, kbps in top_5]}
        await send_to_clients({"type": "bandwidth_update", "data": payload})
    logger.info("Bandwidth calculator task stopped.")

async def packet_sender_callback(packet, loop):
    global captured_packets_buffer, bandwidth_aggregator
    try:
        if (conv_key := get_canonical_conversation_key(packet)):
            update_conversation_tracker(packet, conv_key)
        packet_index = len(captured_packets_buffer); captured_packets_buffer.append(packet) 
        packet_data_for_client = get_packet_summary_data(packet, packet_index)
        asyncio.create_task(send_to_clients({"type": "packet_summary", "data": packet_data_for_client}))
        await check_for_port_scan(packet, loop)
        if (conv_id := get_conversation_id(packet)): bandwidth_aggregator[conv_id] = bandwidth_aggregator.get(conv_id, 0) + len(packet)
    except Exception as e:
        logger.error(f"Error in packet_sender_callback: {e}", exc_info=True)

def sniffing_loop(interface_name: str, stop_event: threading.Event, loop: asyncio.AbstractEventLoop):
    logger.info(f"Sniffing Thread: Starting capture on {interface_name}")
    sniff(iface=interface_name, prn=lambda pkt: asyncio.run_coroutine_threadsafe(packet_sender_callback(pkt, loop), loop), stop_filter=lambda p: stop_event.is_set(), store=0)
    msg = f"Capture stopped. {len(captured_packets_buffer)} packets buffered."
    logger.info(f"Sniffing Thread: Stopped. {len(captured_packets_buffer)} packets in buffer.")
    asyncio.run_coroutine_threadsafe(send_to_clients({"type": "status", "message": msg}), loop)

async def handler(websocket: WebSocketServerProtocol, path: str = None):
    global sniffing_thread, stop_sniffing_event, captured_packets_buffer, scan_tracker, alerted_scanners, bandwidth_task, bandwidth_aggregator, conversation_tracker
    main_event_loop = asyncio.get_running_loop() 
    CONNECTED_CLIENTS.add(websocket); logger.info(f"Client connected: {websocket.remote_address}")
    try:
        await websocket.send(json.dumps({"type": "interfaces", "data": list_network_interfaces_data()}))
        async for message in websocket:
            try:
                data = json.loads(message); command = data.get("command")
                if command == "get_top_scanners":
                    await websocket.send(json.dumps({"type": "top_scanners_data", "data": get_top_scanners_from_db()}))
                elif command == "start_capture" and not (sniffing_thread and sniffing_thread.is_alive()):
                    if (interface := data.get("interface")):
                        captured_packets_buffer.clear(); scan_tracker.clear(); alerted_scanners.clear(); conversation_tracker.clear(); stop_sniffing_event.clear(); bandwidth_aggregator.clear()
                        sniffing_thread = threading.Thread(target=sniffing_loop, args=(interface, stop_sniffing_event, main_event_loop), daemon=True); sniffing_thread.start()
                        if bandwidth_task and not bandwidth_task.done(): bandwidth_task.cancel()
                        bandwidth_task = asyncio.create_task(bandwidth_calculator_loop())
                        await send_to_clients({"type": "status", "message": f"Capture started on {interface}"})
                elif command == "stop_capture" and sniffing_thread and sniffing_thread.is_alive():
                    stop_sniffing_event.set()
                elif command == "save_capture":
                    if not captured_packets_buffer: await websocket.send(json.dumps({"type": "error", "message": "No packets to save."}))
                    elif sniffing_thread and sniffing_thread.is_alive(): await websocket.send(json.dumps({"type": "error", "message": "Stop capture first."}))
                    else:
                        filepath = os.path.join(CAPTURES_DIR, f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
                        wrpcap(filepath, captured_packets_buffer)
                        await send_to_clients({"type": "status", "message": f"Capture saved to {filepath}"})
                elif command == "get_packet_details":
                    try:
                        if 0 <= (index := int(data.get("index", -1))) < len(captured_packets_buffer):
                            await websocket.send(json.dumps({"type": "packet_details", "data": dissect_packet_details(captured_packets_buffer[index])}))
                        else: await websocket.send(json.dumps({"type": "error", "message": f"Invalid packet index: {index}"}))
                    except (ValueError, TypeError): await websocket.send(json.dumps({"type": "error", "message": "Invalid index format."}))
                elif command == "get_conversation_story":
                    key = tuple(data.get("key", []))
                    if key in conversation_tracker:
                        story = generate_conversation_story(conversation_tracker[key])
                        await websocket.send(json.dumps({"type": "conversation_story", "data": story}))

            except Exception as e: 
                logger.error(f"Error handling client message: {e}", exc_info=True); await websocket.send(json.dumps({"type": "error", "message": str(e)}))
    except Exception as e:
        logger.error(f"Unhandled error in WebSocket handler: {e}", exc_info=True)
    finally:
        CONNECTED_CLIENTS.remove(websocket); logger.info(f"Client connection cleanup: {websocket.remote_address}")

# --- Main Server Execution ---
async def main_server_loop():
    ensure_app_dirs(); initialize_local_intel_db()
    async with websockets.serve(handler, WEBSOCKET_HOST, WEBSOCKET_PORT):
        logger.info(f"--- SP3CTR Backend v{__version__} --- WebSocket Server Ready ---"); logger.info(f"Listening on ws://{WEBSOCKET_HOST}:{WEBSOCKET_PORT}"); await asyncio.Future() 

if __name__ == "__main__":
    if not check_windows_prerequisites() or not verify_db_integrity(): sys.exit(1)
    try: asyncio.run(main_server_loop())
    except KeyboardInterrupt: logger.info("\nSP3CTR Core Backend terminated by user.")
    except Exception as e: show_critical_error_and_exit("SP3CTR - Unhandled Exception", f"A critical error occurred: {e}\n\nPlease check the log file for details.")

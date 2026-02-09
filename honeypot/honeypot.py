import paramiko
import socket
import logging
import threading
import os
import json
from datetime import datetime

logging.basicConfig(
    filename='/app/logs/ssh_honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

paramiko_logger = logging.getLogger("paramiko")
paramiko_logger.setLevel(logging.WARNING)

# JSON log file path
JSON_LOG_FILE = '/app/logs/connections.jsonl'

# Load persistent host key instead of generating
HOST_KEY_FILE = '/app/ssh_host_rsa_key'
if os.path.exists(HOST_KEY_FILE):
    host_key = paramiko.RSAKey.from_private_key_file(HOST_KEY_FILE)
else:
    host_key = paramiko.RSAKey.generate(2048)
    try:
        host_key.write_private_key_file(HOST_KEY_FILE)
    except:
        pass  # If we can't write, just use the generated key

def log_json_event(event_type, client_ip, client_port, **kwargs):
    """Log events to JSON file"""
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event_type,
        "client_ip": client_ip,
        "client_port": client_port
    }
    # Add any additional fields
    event.update(kwargs)
    
    # Append to JSON file
    try:
        with open(JSON_LOG_FILE, 'a') as f:
            json.dump(event, f)
            f.write('\n')
    except Exception as e:
        logging.error(f"Failed to write JSON log: {e}")

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()
    
    def get_banner(self):
        return ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", "en")
    
    def check_auth_password(self, username, password):
        # Log to text file
        logging.info(f"IP: {self.client_ip}:{self.client_port} | User: {username} | Pass: {password}")
        
        # Log to JSON file
        log_json_event(
            "auth_attempt",
            self.client_ip,
            self.client_port,
            username=username,
            password=password,
            auth_type="password"
        )
        
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return "password"
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def handle_connection(client, addr):
    transport = None
    
    # Log connection event
    log_json_event("connection", addr[0], addr[1])
    
    try:
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        transport.add_server_key(host_key)
        
        server = SSHServer(addr[0], addr[1])
        transport.start_server(server=server)
        
        channel = transport.accept(60)
        
        if channel is not None:
            server.event.wait(10)
            channel.close()
            
    except Exception as e:
        logging.error(f"Error from {addr[0]}:{addr[1]}: {e}")
        log_json_event("error", addr[0], addr[1], error=str(e))
    finally:
        # Log disconnection
        log_json_event("disconnection", addr[0], addr[1])
        
        if transport:
            try:
                transport.close()
            except:
                pass

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 22))
    server_socket.listen(100)
    
    print("SSH Honeypot running on port 22...")
    print("Logging to /app/logs/ssh_honeypot.log")
    print("JSON logging to /app/logs/connections.jsonl")
    
    while True:
        client, addr = server_socket.accept()
        print(f"Connection from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_connection, args=(client, addr), daemon=True).start()

if __name__ == '__main__':
    main()

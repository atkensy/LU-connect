
import json
import struct
import time
import logging
import threading

# Importing database and encryption functions
from database import init_db, add_user, verify_user, get_all_users
from encryption import encrypt_message, decrypt_message

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#helper functions
def send_json(conn, data_dict):
    message_str = json.dumps(data_dict)
    encoded = message_str.encode('utf-8')
    length_prefix = struct.pack('>I', len(encoded))
    conn.sendall(length_prefix + encoded)

def recv_json(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]

    chunks = []
    received = 0
    while received < msg_len:
        chunk = conn.recv(msg_len - received)
        if not chunk:
            return None
        chunks.append(chunk)
        received += len(chunk)

    data_str = b''.join(chunks).decode('utf-8')
    return json.loads(data_str)



client_semaphore = threading.Semaphore(3)
active_clients = {}  
clients_lock = threading.Lock()

#handling client connection
def handle_client(conn, addr):
    logging.info("Connection from %s", addr)
    username = None

    try:
        # If the semaphore is full, send waiting updates
        start_wait = time.time()
        acquired = client_semaphore.acquire(blocking=False)
        while not acquired:
            wait_time = int(time.time() - start_wait)
            try:
                send_json(conn, {"type": "waiting", "time": wait_time})
            except Exception as e:
                logging.error("Error sending waiting update: %s", e)
                return
            time.sleep(1)
            acquired = client_semaphore.acquire(blocking=False)

        # Once acquired, inform the client they are connected
        try:
            send_json(conn, {"type": "connected"})
        except Exception as e:
            logging.error("Error sending connected message: %s", e)
            return

        while True:
            message = recv_json(conn)
            if not message:
                # Client closed connection
                break

            msg_type = message.get("type")
            if msg_type == "signup":
                uname = message.get("username")
                pwd_hash = message.get("password_hash")
                if add_user(uname, pwd_hash):
                    response = {"type": "signup", "status": "success"}
                else:
                    response = {
                        "type": "signup",
                        "status": "fail",
                        "error": "Username exists or error occurred"
                    }
                send_json(conn, response)

            elif msg_type == "login":
                uname = message.get("username")
                pwd_hash = message.get("password_hash")
                if verify_user(uname, pwd_hash):
                    username = uname
                    with clients_lock:
                        active_clients[username] = conn
                    response = {"type": "login", "status": "success"}
                else:
                    response = {
                        "type": "login",
                        "status": "fail",
                        "error": "Invalid credentials"
                    }
                send_json(conn, response)

            elif msg_type == "get_users":
                # Return both the full list of registered users and those online
                all_list = get_all_users()  
                with clients_lock:
                    online_list = list(active_clients.keys())  # Currently online users
                response = {
                    "type": "get_users",
                    "all_users": all_list,
                    "online_users": online_list
                }
                send_json(conn, response)

            elif msg_type == "message":
                # Relay encrypted message to the target
                target = message.get("to")
                with clients_lock:
                    target_conn = active_clients.get(target)
                if target_conn:
                    logging.info("Forwarding message from %s to %s", username, target)
                    send_json(target_conn, message)
                else:
                    logging.warning("Target user %s not found for messaging.", target)

            elif msg_type == "file":
                # Handle file transfer, restricted to certain file types
                target = message.get("to")
                filename = message.get("filename", "")
                allowed_extensions = (".docx", ".pdf", ".jpeg", ".jpg", ".png")
                if not filename.lower().endswith(allowed_extensions):
                    logging.warning("File type not allowed: %s", filename)
                    response = {
                        "type": "file",
                        "status": "fail",
                        "error": "File type not allowed"
                    }
                    send_json(conn, response)
                else:
                    with clients_lock:
                        target_conn = active_clients.get(target)
                        if target_conn:
                            logging.info("Forwarding file '%s' from %s to %s", filename, username, target)
                            send_json(target_conn, message)
                        else:
                            logging.warning("Target user %s not available for file transfer.", target)
            else:
                logging.warning("Received unknown message type from %s: %s", addr, msg_type)

    finally:
        logging.info("Connection closed: %s", addr)
        try:
            conn.close()
        except Exception:
            pass
        client_semaphore.release()
        if username:
            with clients_lock:
                active_clients.pop(username, None)
                logging.info("Active clients after disconnect: %s", list(active_clients.keys()))

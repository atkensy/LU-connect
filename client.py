import json
import struct

def send_json(sock, data_dict):
    message_str = json.dumps(data_dict)
    message_bytes = message_str.encode('utf-8')
    length_prefix = struct.pack('>I', len(message_bytes))
    sock.sendall(length_prefix + message_bytes)

def recv_json(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    chunks = []
    received = 0
    while received < msg_len:
        chunk = sock.recv(msg_len - received)
        if not chunk:
            return None
        chunks.append(chunk)
        received += len(chunk)
    data_str = b''.join(chunks).decode('utf-8')
    return json.loads(data_str)

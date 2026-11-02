import json

def send_packet(sock, packet, lock=None):
    data = (json.dumps(packet, separators=(",", ":")) + "\n").encode("utf-8")
    if lock:
        with lock:
            sock.sendall(data)
    else:
        sock.sendall(data)

def receive_packet(reader):
    line = reader.readline()
    if not line:
        return None
    return json.loads(line)

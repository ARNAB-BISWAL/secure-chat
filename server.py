import socket
import threading
import json
import base64
from cipher import encrypt, decrypt
from protocol import send_packet, receive_packet

clients = {}
clients_lock = threading.Lock()

def send_encrypted(client, message):
    packet = {"type": "DATA", "payload": encrypt(json.dumps(message), client["key"])}
    send_packet(client["socket"], packet, client["send_lock"])

def remove_client(username, client):
    with clients_lock:
        if clients.get(username) is client:
            del clients[username]
    try:
        client["socket"].close()
    except OSError:
        pass
    print(f"{username} disconnected")

def handle_client(sock, address):
    reader = sock.makefile("r", encoding="utf-8")
    client = None
    username = None
    try:
        # Registration is the bootstrap handshake: the server must receive the key
        # before it can encrypt later traffic for this client.
        first = receive_packet(reader)
        if not first or first.get("type") != "REGISTER":
            return
        username = first.get("username", "").strip()
        key = first.get("key", "")
        if not username or not key:
            send_packet(sock, {"type": "ERROR", "message": "Username and key are required"})
            return

        with clients_lock:
            if username in clients:
                send_packet(sock, {"type": "ERROR", "message": "Username already taken"})
                return
            client = {"socket": sock, "key": key, "send_lock": threading.Lock()}
            clients[username] = client

        send_encrypted(client, {"type": "REGISTERED", "message": f"Welcome, {username}"})
        print(f"{username} connected from {address}")

        while True:
            packet = receive_packet(reader)
            if packet is None:
                break
            if packet.get("type") != "DATA":
                send_encrypted(client, {"type": "ERROR", "message": "Invalid packet"})
                continue
            try:
                command = json.loads(decrypt(packet["payload"], key))
            except Exception:
                send_encrypted(client, {"type": "ERROR", "message": "Could not decrypt request"})
                continue

            action = command.get("action")
            if action == "QUIT":
                send_encrypted(client, {"type": "GOODBYE", "message": "Goodbye"})
                break

            if action == "LIST":
                with clients_lock:
                    names = sorted(clients.keys())
                send_encrypted(client, {"type": "ONLINE", "users": names})
                continue

            if action in ("SEND", "SENDFILE"):
                target = command.get("to", "").strip()
                with clients_lock:
                    receiver = clients.get(target)
                if not receiver:
                    send_encrypted(client, {"type": "ERROR", "message": f"{target} is not online"})
                    continue

                if action == "SEND":
                    outgoing = {
                        "type": "MESSAGE",
                        "from": username,
                        "text": command.get("text", "")
                    }
                else:
                    try:
                        raw = base64.b64decode(command["content"], validate=True)
                    except Exception:
                        send_encrypted(client, {"type": "ERROR", "message": "Invalid file data"})
                        continue
                    outgoing = {
                        "type": "FILE",
                        "from": username,
                        "filename": command.get("filename", "file.txt"),
                        "content": base64.b64encode(raw).decode("ascii")
                    }

                try:
                    send_encrypted(receiver, outgoing)
                    send_encrypted(client, {"type": "OK", "message": f"Sent to {target}"})
                except OSError:
                    send_encrypted(client, {"type": "ERROR", "message": f"Could not deliver to {target}"})
                continue

            send_encrypted(client, {"type": "ERROR", "message": "Unknown command"})
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print("Client error:", e)
    finally:
        if client and username:
            remove_client(username, client)
        else:
            try:
                sock.close()
            except OSError:
                pass

def main():
    host = "0.0.0.0"
    port = 5000
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    print(f"Secure chat server listening on port {port}")
    try:
        while True:
            sock, address = server.accept()
            threading.Thread(target=handle_client, args=(sock, address), daemon=True).start()
    except KeyboardInterrupt:
        print("\nServer shutting down")
    finally:
        server.close()

if __name__ == "__main__":
    main()

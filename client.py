import socket
import threading
import json
import base64
import os
import sys
from cipher import encrypt, decrypt
from protocol import send_packet, receive_packet

MAX_FILE_SIZE = 1024 * 1024

def receiver_loop(reader, key):
    while True:
        try:
            packet = receive_packet(reader)
            if packet is None:
                print("\nServer disconnected")
                break
            if packet.get("type") == "ERROR":
                print("\nServer:", packet.get("message"))
                continue
            if packet.get("type") != "DATA":
                print("\nUnexpected server response")
                continue
            message = json.loads(decrypt(packet["payload"], key))
            kind = message.get("type")
            if kind == "MESSAGE":
                print(f"\n[{message['from']}] {message['text']}")
            elif kind == "FILE":
                data = base64.b64decode(message["content"])
                name = "received_" + os.path.basename(message.get("filename", "file.txt"))
                with open(name, "wb") as f:
                    f.write(data)
                print(f"\nFile received from {message['from']}: {name} ({len(data)} bytes)")
            elif kind == "ONLINE":
                print("\nOnline:", ", ".join(message.get("users", [])))
            else:
                print("\nServer:", message.get("message", message))
        except Exception as e:
            print("\nReceive error:", e)
            break

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    username = input("Username: ").strip()
    key = input("Encryption key: ")
    if not username or not key:
        print("Username and key are required")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        reader = sock.makefile("r", encoding="utf-8")
        send_packet(sock, {"type": "REGISTER", "username": username, "key": key})
        reply = receive_packet(reader)
        if not reply:
            print("No response from server")
            return
        if reply.get("type") == "ERROR":
            print("Registration failed:", reply.get("message"))
            return
        if reply.get("type") != "DATA":
            print("Invalid registration response")
            return
        print(json.loads(decrypt(reply["payload"], key)).get("message", "Registered"))

        threading.Thread(target=receiver_loop, args=(reader, key), daemon=True).start()
        print("\nCommands:")
        print("  SEND TO username: message")
        print("  SENDFILE TO username: path/to/file.txt")
        print("  LIST")
        print("  QUIT")

        while True:
            line = input(f"{username}$ ").strip()
            if not line:
                continue
            if line.upper() == "QUIT":
                action = {"action": "QUIT"}
                send_packet(sock, {"type": "DATA", "payload": encrypt(json.dumps(action), key)})
                break
            elif line.upper() == "LIST":
                action = {"action": "LIST"}
            elif line.upper().startswith("SEND TO "):
                rest = line[8:]
                if ":" not in rest:
                    print("Format: SEND TO username: message")
                    continue
                target, message = rest.split(":", 1)
                action = {"action": "SEND", "to": target.strip(), "text": message.strip()}
            elif line.upper().startswith("SENDFILE TO "):
                rest = line[12:]
                if ":" not in rest:
                    print("Format: SENDFILE TO username: filepath")
                    continue
                target, path = rest.split(":", 1)
                path = path.strip().strip('"')
                if not os.path.isfile(path):
                    print("File not found")
                    continue
                if not path.lower().endswith(".txt"):
                    print("Only .txt files are supported")
                    continue
                if os.path.getsize(path) > MAX_FILE_SIZE:
                    print("File exceeds 1 MB limit")
                    continue
                with open(path, "rb") as f:
                    content = base64.b64encode(f.read()).decode("ascii")
                action = {
                    "action": "SENDFILE",
                    "to": target.strip(),
                    "filename": os.path.basename(path),
                    "content": content
                }
            else:
                print("Unknown command")
                continue

            send_packet(sock, {"type": "DATA", "payload": encrypt(json.dumps(action), key)})
    except (OSError, ValueError) as e:
        print("Connection error:", e)
    finally:
        sock.close()

if __name__ == "__main__":
    main()

# Secure Command-Line Chat Application (Python)

A TCP command-line chat application with multiple simultaneous clients, per-client symmetric keys, encrypted chat messages, and encrypted `.txt` file transfer.

## Requirements
- Python 3.9 or newer
- No external Python packages

## Files
- `server.py` — multi-client TCP server
- `client.py` — command-line client
- `cipher.py` — repeating-key XOR encryption/decryption
- `protocol.py` — newline-delimited JSON packet framing

## Run

Open a terminal in this folder and start the server:

```bash
python server.py
```

On the same computer, open another terminal for each client:

```bash
python client.py
```

To connect from another computer on the same network:

```bash
python client.py SERVER_IP 5000
```

Register each client with a unique username and a key. The sender and receiver use their own keys; they do not need to share the same key.

## Commands

```text
SEND TO monk: Hello, There!
SENDFILE TO monk: notes.txt
LIST
QUIT
```

Only `.txt` files up to 1 MB are accepted. Received files are saved in the client's current folder with a `received_` prefix.

## How it works

1. The server accepts each TCP connection in a separate thread.
2. A client registers a username and symmetric key.
3. After registration, client commands and server responses are encrypted.
4. For a chat message, the server decrypts it using the sender's key and encrypts it again using the recipient's key.
5. File contents follow the same decrypt-and-re-encrypt route.
6. A disconnected client is removed from the online-client table.

## Important security note

This is an educational demonstration, not production-grade security. It uses repeating-key XOR, which is weak and can be broken; it provides no authentication or integrity protection. The initial registration packet carries the username and key as a bootstrap handshake because the server cannot encrypt a key it has not received yet. Therefore, registration itself is not encrypted. The assignment's hop-by-hop design means the server temporarily handles plaintext while routing messages; it is not end-to-end encryption.

For a real application, use TLS and a vetted authenticated-encryption library rather than this cipher.

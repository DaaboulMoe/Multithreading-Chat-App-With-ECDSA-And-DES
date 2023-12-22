import json
import socket
import threading
from Encrypt import des_decrypt
import ECDSA
import ast

HEADER = 512
PORT = 9000
SERVER = "localhost"
ADDR = (SERVER, PORT)
FORMAT = "utf-8"
DISCONNECT = "!DISCONNECT"
USERNAME = "!USERNAME"

desKey = "1234567890abcdef"
clients = {}
publicKeys = {} #Dictionary to store public keys

def unique_username(user, sender_port):
    for client in clients:
        if clients[client][1] == user and sender_port != client:
            print(f"Username {user} exists")
            return 0
    return 1

def change_username(new_username, sender_socket, sender_port):
    if not unique_username(new_username, sender_port):
        sender_socket.send(USERNAME.encode(FORMAT))
    clients[sender_port][1] = new_username
    return

def send_private(message, originalMessage):
    # Decrypt the message using DES decryption, used .split("\00")[0] to remove the extra padding to the string added.
    target_username = des_decrypt(message[2],desKey).split("\00")[0]
    target_socket = None
    
    # Find destination user/port
    for port in clients: 
        if(clients[port][1] ==target_username):
            target_socket = clients[port][0]
    
    if target_socket:
        # Send the original encrypted message to decrypt and process on client side
        target_socket.send(originalMessage.encode(FORMAT))
        print("Sent private message to ",target_username)

def send_broadcast(originalMessage, sender_port=None):
    # No need to decrypt as message will be sent to everyone 
    items = [(key, value[0]) for key, value in clients.items() if value]
    for port, sock in items:
        if port != sender_port:
            sock.send(originalMessage.encode(FORMAT))

def disconnect_user(username, port):
    print(f"[DISCONNECTED] {username}")
    clients.pop(port)
    disconnect_message = f"{username} DISCONNECTED"
    send_broadcast(disconnect_message.encode(FORMAT))
    print(clients)
    return

def forward_message(sender_socket, message, sender_port):
    # Messages will be sent in the form of [message, sender_username]
    originalMessage = message
    message = json.loads(message.encode(FORMAT))
    # print(message)
    if message:  
        # If username is not unique, notify client
        if message[0] == 'username':
            publicKey = message[2]
            publicKeys[message[1]] = publicKey
            print("Public Keys: " , publicKeys)
            return change_username(message[1], sender_socket, sender_port)

        # Send private message to specific port
        elif message[0] == 0:
            ciphertext = message[3][0]
            signature = message[4]
            username = des_decrypt(message[1],desKey).split("\00")[0]
            usersPublicKey = publicKeys[username]
            authenticate = ECDSA.verify_signature(usersPublicKey, ciphertext, signature)
            print("Authenticating ",username, "'s private message...", "AUTHENTICATED" if authenticate else "NOT AUTHENTICATED")
            return send_private(message, originalMessage)

        # Send broadcast message to every port except sender's
        else: 
            t = des_decrypt(message[3], desKey).split("\00")[0]
            print(t)
            if t == DISCONNECT:
                disconnected_user = des_decrypt(message[1], desKey).split("\00")[0]
                disconnect_user(disconnected_user, sender_port)
            return send_broadcast(originalMessage, sender_port)

def handle_client(conn, addr):
    print(f"[{addr} CONNECTED]")
    while True:
        data = conn.recv(HEADER).decode(FORMAT)
        # print(data)
        if data == DISCONNECT:
            print(f"[DISCONNECTED] {addr}")
            clients.pop(addr[1])
            break

        elif data:
            forward_message(conn, data, addr[1])
            
    conn.close()

def start():
    # Initiaize Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()

    print(f"[SERVER LISTENING on {SERVER}: {PORT}]")
    
    # Passively listen for incoming connections
    while True:
        conn, addr = server.accept()

        # Save new client in a dictionary in the form of {port: [socket, username]}
        # Will be used later in forwarding
        clients[addr[1]] = [conn,'New Client']

        # Create a new thread to handle this client and start it
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

start()
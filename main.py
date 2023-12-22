import base64
import ECDSA
from flask import Flask, redirect, url_for, render_template, request, session
from threading import Thread 
from Encrypt import des_decrypt, des_encrypt
import socket
import json
import time

app = Flask(__name__)

HEADER = 512
PORT = 9000
SERVER = "localhost"
ADDR = (SERVER, PORT)
FORMAT = "utf-8"
DISCONNECT = "!DISCONNECT"
USERNAME = "!USERNAME"

client = None
users = []
messages = [] # List storing the sent and received messages from every user's point of view
username = ''
desKey = "1234567890abcdef"
clients = {}
username_error = 0

privateKey = ECDSA.create_private_key()

def send(client, message , publicKey = 0):
    tokens = message.split(':', 2)
    serverMsg = []

    # Send username information to server
    if tokens[0] == 'username':
        serverMsg = ["username" , tokens[1] , publicKey] 
        serverMsg = json.dumps(serverMsg).encode(FORMAT)
        client.send(serverMsg)
        return

    # Send private message
    if tokens[0] == 'private': 
        messages.append("ME to "+tokens[1] + " (private) : " + tokens[2])
        # Sign the ciphertext with the private Key so that server can authenticate it
        ciphertext = des_encrypt(tokens[2] , desKey)[0] ;  signature = ECDSA.sign_message(privateKey, ciphertext) 
        serverMsg = [0 ,des_encrypt(username,desKey) , des_encrypt(tokens[1],desKey) , des_encrypt(tokens[2] , desKey), signature]
        print("Signed Private Message With: ",signature)
        print("Me to ",tokens[1]," (private) : ",tokens[2])
 
    # Send broadcast message 
    else: 
        messages.append("ME to all : " + tokens[0]) 
        serverMsg = [1 ,des_encrypt(username,desKey) , des_encrypt("All",desKey) , des_encrypt(message,desKey)]  
        print("ME to all : " , tokens[0]) 
    
    #Send the message after encrypting
    serverMsg = json.dumps(serverMsg).encode(FORMAT)
    client.send(serverMsg) 
    return 

def receive(conn):
    while True:
        message = conn.recv(HEADER).decode(FORMAT) 
        message = json.loads(message.encode(FORMAT)) 
        if type(message) == dict:
            clients = message
            return
        if message:
            msg = ' '
            if message[0] == 1: 
                decryptedMsg = [1 ,des_decrypt(message[1],desKey) , des_decrypt(message[2],desKey) , des_decrypt(message[3],desKey)] 
                msg = f'{decryptedMsg[1]} to all: {decryptedMsg[3]}'
                print("Before decryption: ", message[3])
                print(msg)
            else: 
                decryptedMsg = [0 ,des_decrypt(message[1],desKey).split("\00")[0] , des_decrypt(message[2],desKey).split("\00")[0] , des_decrypt(message[3],desKey).split("\00")[0]]
                #If message sent is private 
                # print("This is the decrypted message: " ,decryptedMsg)
                print("Before decryption: ", message[3])
                msg = f'{decryptedMsg[1]} to me (private): {decryptedMsg[3]}' 
                print(msg)
            messages.append(msg) 
        else:
            break 

def connect_client():
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    t = Thread(target=receive, args=(client,)).start()

@app.route("/", methods=['GET', 'POST'])
def main():
    if request.method == 'POST':
        # Save the username of the client in global variable
        global username
        username = request.form['username']
        print(f'[CONNECTED] {username}')

        # Send the username to the server to update on server side
        # And pass the public key to store on server
        publicKey = ECDSA.create_public_key(privateKey)
        send(client, f'username:{username}',publicKey)
        time.sleep(1)
        global username_error
        if username_error == 1:
            username_error = 0
            return render_template('profile.html', error=username_error)
        
        return redirect(url_for('chat'))
    
    return render_template('profile.html')

@app.route("/chatroom", methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        message = request.form['message']
        send(client,message)
    return render_template('chatroom.html', messages=messages)


def start_app():
    app.run(debug=False, port=0)

if __name__ == "__main__":
    t1 = Thread(target=connect_client)
    t2 = Thread(target=start_app) 

    t1.start()
    t2.start()

     
import socket
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from base64 import b64decode
import json
import threading


# socket type Internet socket AF_INET 
# SOCKET.SOCK_STREAM to use the TCP connection 

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind(("localhost", 5000))


server_socket.listen(5)
print("Waiting for client.....")

client_socket, addr = server_socket.accept()

print("Connected to: ", addr)

if not os.path.exists("keys"):
    os.makedirs("keys")
    
pwd = 'my secret key'

if not os.path.exists("keys/public_key.pem") or not os.path.exists("keys/private_key.pem"):
    rsa_key = RSA.generate(2048)
    private_key = rsa_key
    public_key = rsa_key.publickey()


    # Export the keys as bytes
    my_public_key = public_key.export_key()
    
    # export an RSA private key and protect it with a password, so that it is resistant to brute force attacks:
    my_private_key = private_key.export_key(passphrase=pwd)

    # Save the keys
    with open("keys/public_key.pem", "wb") as f:
        f.write(my_public_key)

    with open("keys/private_key.pem", "wb") as f:
        f.write(my_private_key)
    print("[SERVER]: Public and Private Keys generated Successfully!...")
else:
    print("[SERVER]: Using existing Public and Private Keys...")
    with open("keys/public_key.pem", "rb") as f:
        my_public_key = f.read()


client_socket.sendall(my_public_key)

with open("keys/private_key.pem", "rb") as f:
        read_private_key = RSA.import_key(f.read(),passphrase=pwd)

# recieve the session key from client

key = client_socket.recv(1024).decode("utf-8")


def decryptKey(encrypted_key, key ):
    decodedKey = b64decode(key)
    # PKCS = Public-Key Cryptography Standard
    # Big Bum Bum by Kidd Carder, Mavo
    rsa_cipher = PKCS1_OAEP.new(
        encrypted_key,
        hashAlgo=SHA256
    )
    aes_key = rsa_cipher.decrypt(decodedKey)
    print("AES session key successfully recovered by server.")
    
    return aes_key

decryptedKey = decryptKey(read_private_key, key)


def decrypt(message, session_key, nonce, tag):
    try:
        decodedMessage =  b64decode(message)
        decodednonce = b64decode(nonce)
        tag_bytes = b64decode(tag)

        print("[SERVER]: Client message and crypto artifacts decoded successfully.")
        # print("[SERVER]: client message decoded successfully..")
        # print("[SERVER]: clinet AES-GCM nonce decoded successfully..")
        # print("[SERVER]: client AES encrypted key recieved and decoded successfully..")
            
        print("[SERVER]: server is ready to decrypt message using PKCS1_OAEP.. ")
        
        cipher = AES.new(session_key, AES.MODE_GCM, nonce = decodednonce)
        print("[SERVER]: A new AES GCM class has been created...")
        
        dycrptedText = cipher.decrypt_and_verify(decodedMessage, tag_bytes)
        print("[SERVER]: Message decrypted and verified.")
        
        
        return dycrptedText.decode('utf-8')
    
    
        
    except(ValueError, KeyError, UnicodeDecodeError,
        json.JSONDecodeError) as e:
        print("dycrption failed...", e)
        return None

# Continuous loop to handle incoming messages until client disconnects
print("[SERVER]: Ready to receive messages...")


def communication():
        buffer = b""

        while True:
            # Collect data until a complete JSON line arrives
            # Keeps collecting TCP data until one complete message arrives.
            while b"\n" not in buffer:

                data = client_socket.recv(4096)

                if not data:
                    if buffer:
                        print("[SERVER]: Incomplete message received.")
                    else:
                        print("[SERVER]: Client disconnected.")
                    return

                buffer += data

                if len(buffer) > 1024 * 1024:
                    print("[SERVER]: Message exceeds maximum size.")
                    return

            # Extract one message and preserve remaining bytes
            json_string, buffer = buffer.split(b"\n", 1)


            try:

                json_data = json.loads(json_string.decode('utf-8'))

                # print("Data sent to backend: ", json_data)

                ciphertext = json_data["message"]
                nonce = json_data["nonce"]
                tag = json_data["tag"]

            
                    
                plainText = decrypt(ciphertext, decryptedKey, nonce, tag)

                if plainText is not None:

                    print("\n[SERVER]: Decrypted Text:", plainText)

                    response = "Received and Decrypted Successfully\n"

                else:

                    response = "Message Decryption Failed\n"

                client_socket.sendall(response.encode("utf-8"))
                
            except Exception as err:
                print("[SERVER]: Error processing packet:", err)
                client_socket.sendall(b"Invalid message received\n")
                break


communication_thread = threading.Thread(target=communication)

communication_thread.start()
communication_thread.join()



        
client_socket.close()
server_socket.close()
print("[SERVER]: Server shut down.")

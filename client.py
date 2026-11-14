import socket
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64decode, b64encode
from secrets import token_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import threading

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect(("localhost", 5000))
print("waiting to connect to server")

key = token_bytes(16)
print("[CLIENT]: AES sesion key generated..")
    
# Defines the hybrid encryption function taking the text and the receiver's public key.
def encryptData(plainText):
    
    encodedText = plainText.encode()
    print("[CLIENT]: Converts the raw message string into bytes...")
    
    
    # Initializes AES in GCM mode (Galois/Counter Mode), which provides both encryption and data integrity authentication.
    cipher = AES.new(key, AES.MODE_GCM)
    print("[CLIENT]: new AES class created..")
    
    
    # Encrypts the message and generates a cryptographic authentication tag to prevent tampering.
    cipherText, tag = cipher.encrypt_and_digest(encodedText)
    
    print("[CLIENT]: message encrypted along with a cryptographic authentication tag..")
    
    
    # Encodes the cryptographic binary artifacts into Base64 strings.
    nonce = b64encode(cipher.nonce).decode("utf-8") 
    print("[CLIENT]: cipher nonce created and decoded")
    
    decoedTag = b64encode(tag).decode("utf-8")
    print("[CLIENT]: tag decoded..")
    
    decodedText = b64encode(cipherText).decode("utf-8")
    print("[CLIENT]: Encrypted message decoded")
    
    
    
    return decodedText, nonce, decoedTag

def encryptSessionKey(receipent_key, session_key):
    # Prepares the RSA asymmetric cipher using OAEP padding and SHA-256.
        encrypted_key = PKCS1_OAEP.new(
            receipent_key,
            hashAlgo=SHA256
        )
        
        print("[CLIENT]: RSA PKCS#1_OAEP class created to encrypt AES session key..\n")
        
        encrypted_aes_key_bytes = encrypted_key.encrypt(session_key)
        print("[CLIENT]: AES session key encrypted with SERVER RSA Public-Key Cryptography Standard (PKCS1_OAEP)..\n")
        
        encrypted_key_b64 = b64encode(encrypted_aes_key_bytes).decode("utf-8")
        print("[CLIENT]: AES encrypted session key decoed.... \n")
        
        return encrypted_key_b64
 




public_key  = client.recv(1024).decode("utf-8")
    
if not public_key :
    print("[CLIENT]: No public key provided...")
else:
    print("[CLIENT]: Public Key recieved..")
    
rsa_pub_key_obj = RSA.import_key(public_key)

sessionKey = encryptSessionKey(rsa_pub_key_obj, key)


client.sendall(sessionKey.encode("utf-8") + b"\n")

print("----- Type 'end' to end the conversation with Server -----")

def client_com():
    while True:
        input_message = input("\nEnter message for server: ")
        
        if input_message.strip().lower() == "end":
            print("[CLIENT]: Ending conversation...")
            break
        
        if not input_message.strip():
            continue # Skip empty messages


        
        # Encrypt message components
        client_message, nonce, tag = encryptData(input_message)

        # Bundle components into dictionary
        data = {
            "nonce": nonce,
            "message": client_message,
            "tag": tag
        }

        # Convert to JSON with a newline delimiter and send
        json_dump = json.dumps(data) + "\n"
        client.sendall(json_dump.encode("utf-8"))

        print("--- Sent to Server ---")
        print("Encrypted message (B64):", client_message)

        # Wait for and read the server's response
        response = client.recv(1024).decode()
        print('Server response:', response)


communication_thread = threading.Thread(target=client_com)

communication_thread.start()
communication_thread.join()

# Close connection when loop breaks
client.close()
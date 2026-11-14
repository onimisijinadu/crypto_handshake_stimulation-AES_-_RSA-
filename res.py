from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from secrets import token_bytes

key = token_bytes(16)  # AES-128 requires a 16-byte key

def encryptCode(plainText):
    """
    Encrypts the given plaintext using AES encryption in CTR mode.

    :param plaintext: The plaintext string to encrypt.
    :return: A tuple containing the ciphertext and the nonce used for encryption.
    """
    
    # CTR mode does not require padding, encode the plaintext directly to bytes
    encodedText = plainText.encode('utf-8')
    print(f"Encoded text: {encodedText}")
    
    #create a new AES Cipher object in CTR mode with a random nonce
    cipher = AES.new(key, AES.MODE_CTR)
    
    # encrypt the encoded text
    cipherText = cipher.encrypt(encodedText)
    print(f"Cipher text: {cipherText}")
    # Encode the nonce to a string for storage or transmission
    nonce = b64encode(cipher.nonce).decode('utf-8')
    
    
    # Encode the cipherText to a string for storage or transmission
    encodedTextStr = b64encode(cipherText).decode("utf-8")
    print(f"DecodedCipherText: {encodedTextStr}")
    
    return encodedTextStr, nonce


#function to decrypt text
def decryptInput(message, nonce):
    """
    Decrypts the given encrypted message using AES decryption in CTR mode.

    :param message: The message string to encrypt.
    :return: A tuple containing the ciphertext and the nonce used for encryption.
    """
    
    try:
        decodedMessage = b64decode(message)
        decodedNonce = b64decode(nonce)
        
        cipher = AES.new(key, AES.MODE_CTR, nonce = decodedNonce)
        
        cipherText = cipher.decrypt(decodedMessage)
        
        return cipherText.decode("utf-8")
    
    except (ValueError, KeyError):
        
        print("Unable to decrypt")
        
        return None


# Input, encryption and Decryption execution

message = input("Enter your Message: ")

cipherMessage, nonce = encryptCode(message)

print("\n--Encryption OutPut--")
print(f"CiperText: {cipherMessage}")
print(f"Nonce result: {nonce}")


decipherMessage = decryptInput(cipherMessage, nonce)

print("\n---Decrypted Message---")
print(f"Decrypted Text: {decipherMessage}")
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from secrets import token_bytes


# key should contain 16 bits of random bytes
key=token_bytes(16)

def encryptToken(message):
        # Encrypts the given plaintext using AES encryption in CTR mode.
    # encypt messages 
    # @param message paramenter to receive the message to encrypt
    plaintext = (message).encode("utf-8")
    
    cipher = AES.new(key, AES.MODE_CTR)
    
    cipherText = cipher.encrypt(plaintext)
    
    nonce = b64encode(cipher.nonce).decode("utf-8")
    EncryptText = b64encode(cipherText).decode("utf-8")
    
    return EncryptText, nonce

def decrptText(text, nonce):
    try:
        textDecode = b64decode(text)
        nonceDecode = b64decode(nonce)
        cipher = AES.mew(key, AES.MODE_CTR, nonce = nonceDecode)
        plaintext = cipher.decode(textDecode)
        return plaintext.decode("utf-8")
    except(ValueError, KeyError):
        print("Failed Decryption")
        return None
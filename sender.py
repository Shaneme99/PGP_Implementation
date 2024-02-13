from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def main():

    generate_keys()

    # Getting text
    data = input("Enter text: ").encode()
    aes_key, notification = encrypt_message(data)
    hash = get_hash(data)

    #Finding key
    recipient_key = generate_keys()
    cipher_rsa = PKCS1_OAEP.new(recipient_key)

    # Getting sender key
    send_priv = RSA.import_key(open("sender_priv.pem").read())
    sender_private = PKCS1_OAEP.new(send_priv)


    #Encoding
    encoded_hash = sender_private.encrypt(hash)
    encode_key = cipher_rsa.encrypt(aes_key)
    #writing results
    with open("encrypted.txt", "ab") as binary_file:
        binary_file.write(b'00')
        binary_file.write(encoded_hash)
        binary_file.write(b'00')
        binary_file.write(encode_key)
    # Did it!
    print("Message Sent: ")
    print(notification)
    print("Symmetric Key: ", encode_key)
    print("Encoded Hash: ", encoded_hash)


def generate_keys():
    # Code to generate and recieve RSA keys
    try:
        recipient_key = RSA.import_key(open("reciever_public.pem").read())
    except FileNotFoundError:
        raise Exception("Please run reciever.py first to finish key generation.")
    # Generating Key
    keys = RSA.generate(1024)
    private_key = keys.export_key()
    public_key = keys.publickey().export_key()
    
    with open("sender.pem","wb") as sender_key:
        sender_key.write(public_key)    

    with open("sender_priv.pem","wb") as sender_priv:
        sender_priv.write(private_key)
    return recipient_key


def get_hash(message):
    #Returns the hash of the plaintext message
    hash = SHA256.new()
    hash.update(message)
    print(hash.digest())
    return hash.digest()


def encrypt_message(message):
    #Encrypts the plain text message
    key = b'Sixteen byte key'

    cipher = AES.new(key, AES.MODE_EAX)

    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(message)

    with open("encrypted.txt","wb") as binary_file:
        binary_file.write(nonce)
        binary_file.write(b'00')
        binary_file.write(ciphertext)
        binary_file.write(b'00')
        binary_file.write(tag)
    message = "Encoded Message: "+ str(ciphertext)
    return key, message

main()
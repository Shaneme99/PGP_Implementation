from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 

def main():

    sender_public = generate_keys()

    key, nonce, ciphertext, tag, hash = get_data()
    
    cipher, plaintext = decrypt_message(key, nonce,ciphertext)

    hash = sender_public.decrypt(hash)
    hash_confirm = SHA256.new()
    hash_confirm.update(plaintext)

    if(hash == hash_confirm.digest()):
        print("Hashes Authenticated")
    try:

        cipher.verify(tag)

        print("Message:", plaintext.decode())

    except ValueError:

        print("Key incorrect or message corrupted")

def decrypt_message(key, nonce,ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return cipher, plaintext

def generate_keys():
    keys = RSA.generate(1024)
    private_key = keys.export_key()
    public_key = keys.publickey().export_key()

    with open("reciever_public.pem", "wb") as f:
        f.write(public_key)
    with open("reciever_private.pem", "wb") as f:
        f.write(private_key)
    try:
        send_pub = RSA.import_key(open("sender_priv.pem").read())
    except FileNotFoundError:
        raise Exception("Keys created and shared. Now, run sender.py.")
    sender_public = PKCS1_OAEP.new(send_pub)
    return sender_public

def get_data():
    with open("encrypted.txt","rb") as binary_file:
        data = binary_file.read()
    data = data.split(b'00')
    key = b'Sixteen byte key'
    nonce = data[0]
    ciphertext = data[1]
    tag = data[2]
    hash = data[3]
    return key, nonce, ciphertext, tag, hash
main()
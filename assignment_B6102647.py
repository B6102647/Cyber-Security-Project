from Cryptodome.Cipher import AES
from hashlib import sha512
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
import base64

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    plaintext = base64.b64encode(plaintext)
    enc = encrypt(plaintext, key)
    
    split_file_name = file_name.split('.')  
    with open(split_file_name[0]+"_encryption."+ split_file_name[1], 'wb') as fo:
        fo.write(enc)
    return enc

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    dec = base64.b64decode(dec)

    split_file_name = file_name.split('.')
    split2 =  split_file_name[0].split('_')
    file_name_dec = split2[0]

    with open(file_name_dec+"_decryption."+ split_file_name[1], 'wb') as fo:
        fo.write(dec)
    return dec.decode(errors='ignore')


key = b'1234sfsfdsafasdf'

msg = encrypt_file('file.txt', key)
decrypt_file('file_encryption.txt', key)

encrypt_file('Assignment-CyberSecurity.pdf', key)
decrypt_file('Assignment-CyberSecurity_encryption.pdf', key)


######### Digital Signature #############
keyPair = RSA.generate(bits=1024)
print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

# RSA sign the message
hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
signature = pow(hash, keyPair.d, keyPair.n)
print("\nSignature:", hex(signature))

# RSA verify signature
hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
hashFromSignature = pow(signature, keyPair.e, keyPair.n)
print("\nSignature valid:", hash == hashFromSignature)
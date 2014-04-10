from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#Generate keys with RSA.py
private = RSA.importKey(open('private.pem', 'r+b').read())
public = RSA.importKey(open('public.pem', 'r+b').read())

message = b'To be encrypted'
cipher = PKCS1_OAEP.new(public)
ciphertext = cipher.encrypt(message)

cipher = PKCS1_OAEP.new(private)
dmessage = cipher.decrypt(ciphertext)

print(dmessage)
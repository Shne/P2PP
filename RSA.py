from Crypto.PublicKey import RSA

key = RSA.generate(2048)

f = open('private.pem','w+b')
f.write(key.exportKey('PEM'))
f.close()

f = open('public.pem','w+b')
f.write(key.publickey().exportKey('PEM'))
f.close()
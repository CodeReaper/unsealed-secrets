import sys
import M2Crypto
import M2Crypto.Rand
import M2Crypto.RSA
import base64
import json
import os

if len(sys.argv) != 2:
	print sys.argv[0], " sealed.json"
	sys.exit(1)

private_key = os.path.dirname(os.path.realpath(__file__)) + "/../_shared/private_key.pem"
sealedfile = open(sys.argv[1])
sealed = sealedfile.read()
sealedfile.close()

sealed = json.loads(sealed)

token = sealed["token"]
payload = sealed["payload"]

private_key = M2Crypto.RSA.load_key(private_key)
token = private_key.private_decrypt(base64.b64decode(token), M2Crypto.RSA.pkcs1_padding)

cipher='rc4'
iv = ""
enc = M2Crypto.EVP.Cipher(cipher, token, iv, 0)
unsealed = enc.update(base64.b64decode(payload))
unsealed += enc.final()

print 'unsealed:'
print unsealed
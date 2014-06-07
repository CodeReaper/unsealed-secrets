import sys
import M2Crypto
import M2Crypto.Rand
import M2Crypto.RSA
import base64
import json
import os

if len(sys.argv) != 3:
	print sys.argv[0], " payload.json sealed.json"
	sys.exit(1)

public_key = os.path.dirname(os.path.realpath(__file__)) + "/../_shared/public_key.pem"
messagefile = open(sys.argv[1])
data = messagefile.read()
messagefile.close()

public_key = M2Crypto.RSA.load_pub_key(public_key)
randdata = M2Crypto.Rand.rand_bytes(16)
msg = public_key.public_encrypt(randdata,M2Crypto.RSA.pkcs1_padding)
token = base64.b64encode(msg)

cipher='rc4'
iv = ""
enc = M2Crypto.EVP.Cipher(cipher, randdata, iv, 1)
payload = enc.update(data)
payload += enc.final()
payload = base64.b64encode(payload)

j = {'token':token,'payload':payload}

f = open(sys.argv[2],'w')
f.write(json.dumps(j))
f.close()
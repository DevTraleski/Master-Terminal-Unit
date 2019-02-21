import sys
import base64

db = open('db', 'a')

for i in range(1, int(sys.argv[1]) + 1):
	nonce = str(base64.b32encode(str(i).encode('utf-8')))[2:-1]
	db.write('serial' + str(i) +':' + nonce + '\n')

db.close()

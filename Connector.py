import http.client
import json

from Crypto.Cipher import AES

import pyotp
import hashlib
import binascii
import os

class Connector:

	database = {}
	address = {}		
	responses = {}
	readings = "Null"

	def __init__(self):
		with open("db", "r") as f:
			data = f.readlines()
 		
		selectedGateway = "none"
		for line in data:
			if line[:1] == "!":
				selectedGateway = line[1:-1]
				self.database[selectedGateway] = {}
			else:
				infos = line.split(":")
				serial = infos[0]
				nonce = infos[1]
				self.database[selectedGateway][serial] = nonce[:-1]
		print(self.database)

		with open("address", "r") as f:
			add = f.readlines()
		
		for line in add:
			info = line.split(":")
			self.address[info[0]] = info[1][:-1]

		#print(self.address)

	def checkToken(self, token):
		print(token)
		conn = http.client.HTTPSConnection('172.0.17.2', 9443)
		header = {'Authorization' : 'Basic YWRtaW46YWRtaW4=', 'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
		body = 'token=' + token.split(' ')[1]
		conn.request('POST', '/oauth2/introspect', body, header)
		response = conn.getresponse()
		jsonResponse = json.loads(response.read().decode("utf-8"))
		if jsonResponse.get('active') == True:
			return True
		else:
			return False

	def req(self, token, requisition, gateway):
		if gateway in self.address.keys():
			conn = http.client.HTTPSConnection(self.address[gateway], 4000)
			header = {'Authorization' : token, 'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
			body = 'req=' + requisition
			conn.request('GET', '/search', body, header)
			response = conn.getresponse()
			return response.read().decode("utf-8")
		else:
			return "Gateway not found"



	def receive(self, data):
		dict = json.loads(data)

		for serial in self.database['gateway_a'].keys():
			if serial in dict.keys():
				decoded = self._decode(dict[serial], self.database['gateway_a'][serial])
				self.responses[serial] = decoded

		print(self.responses)
		self.readings = "Null"
		self.readings = json.dumps(self.responses)
		return "Received"

	def returnData(self):
		return self.readings
	

	def _decode(self, payload, key):
		print("Decoding")
		dict = json.loads(payload)
		print(dict)

		totp = pyotp.TOTP(key)
		totpKey = totp.at(dict['timestamp'])
		print("TOTP Key: " + totpKey)
		m = hashlib.md5()
		m.update(totpKey.encode("UTF-8"))
		hashKey = m.hexdigest()[:16]

		IV = binascii.unhexlify(dict['iv'])
		decipher = AES.new(hashKey, AES.MODE_CBC, IV=IV)
		unhexData = binascii.unhexlify(dict['data'])
		print("Unhexed Data: " + str(unhexData))
		plainText = decipher.decrypt(unhexData)
		plainText = plainText[:-plainText[-1]]
		plainText = plainText.decode("utf-8")
		return plainText

	def setup(self, gateway, serial, gnonce, dtlsk):
		if serial in self.database[gateway].keys():
			nonce = self.database[gateway][serial]
			dict = { 'gnonce' : gnonce, 'dtlsk' : dtlsk }
			jsonStr = json.dumps(dict)

			IV = os.urandom(16)
			encryptor = AES.new(nonce, AES.MODE_CBC, IV=IV)
			length = 16 - (len(jsonStr) % 16)
			addData = bytes([length]) * length
			response = jsonStr + addData.decode('utf-8')
			cipherText = encryptor.encrypt(response)

			hexIV = str(binascii.hexlify(IV).upper())[2:-1]
			dictR = { 'data' :  str(binascii.hexlify(cipherText).upper())[2:-1], 'iv' : hexIV}
			payload = json.dumps(dictR)
			return payload
		else:
			return '{"error":"Serial not found on database"}'

		

#Test
#print(Connector().req("Search", "gadeway"))

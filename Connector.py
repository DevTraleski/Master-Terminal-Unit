import http.client
import json

from Crypto.Cipher import AES

import pyotp
import hashlib
import binascii
import os
import time
import datetime

class Connector:
	alerts = []

	database = {}
	address = {}		

	def __init__(self):
		self._loadDB()

	def _loadDB(self):
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

		with open("address", "r") as f:
			add = f.readlines()
		for line in add:
			info = line.split(":")
			self.address[info[0]] = info[1][:-1]

		with open("alerts", "r") as f:
			add = f.readlines()

		for line in add:
			info = line.split(";")
			self.alerts.append(info[0] + " " + info[1] + " " + info[2][:-1])

	def checkToken(self, token):
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
			self.readings = "Null"
			self.responses = {}
			conn = http.client.HTTPSConnection(self.address[gateway], 4000)
			header = {'Authorization' : token, 'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
			body = 'req=' + requisition
			conn.request('GET', '/search', body, header)
			response = conn.getresponse()

			dict = json.loads(response.read().decode("utf-8"))

			responses = {}
			for serial in self.database['gateway_a'].keys():
				if serial in dict.keys():
					decoded = self._decode(dict[serial], self.database['gateway_a'][serial])
					responses[serial] = decoded

			return json.dumps(responses)
		else:
			return "Gateway not found"


	def _decode(self, payload, key):
		dict = json.loads(payload)

		totp = pyotp.TOTP(key)
		totpKey = totp.at(dict['timestamp'])
		m = hashlib.md5()
		m.update(totpKey.encode("UTF-8"))
		hashKey = m.hexdigest()[:16]

		IV = binascii.unhexlify(dict['iv'])
		decipher = AES.new(hashKey, AES.MODE_CBC, IV=IV)
		unhexData = binascii.unhexlify(dict['data'])
		plainText = decipher.decrypt(unhexData)
		plainText = plainText[:-plainText[-1]]
		plainText = plainText.decode("utf-8")
		return plainText

	def setup(self, gateway, serial, gnonce, dtlsk):
		if serial in self.database[gateway].keys():
			nonce = self.database[gateway][serial]
			dict = { 'gnonce' : gnonce, 'dtlsk' : dtlsk }
			jsonStr = json.dumps(dict)

			m = hashlib.md5()
			m.update(nonce.encode("UTF-8"))
			hashKey = m.hexdigest()[:16]

			IV = os.urandom(16)
			encryptor = AES.new(hashKey, AES.MODE_CBC, IV=IV)
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

		
	def receiveAlert(self, payload, gateway):

		dict = json.loads(payload)

		serial = dict['serial']

		if serial in self.database[gateway].keys():
			plainText = self._decode(payload, self.database[gateway][serial])
			print(plainText)
			with open("alerts", "a") as f:
				f.write(serial + ';' + plainText + ';' + datetime.datetime.fromtimestamp(dict['timestamp']).strftime('%Y-%m-%d %H:%M:%S') + '\n')
			self._loadDB()
			
	def returnAlerts(self):
		self._loadDB()
		return str(self.alerts)

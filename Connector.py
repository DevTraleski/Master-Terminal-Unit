import http.client
import json

class Connector:

	database = {}
	address = {}		

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
				lmk = infos[2][:-1]
				self.database[selectedGateway][serial] = [nonce, lmk]
		#print(self.database)

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
		body = 'token=' + token
		conn.request('POST', '/oauth2/introspect', body, header)
		response = conn.getresponse()
		jsonResponse = json.loads(response.read().decode("utf-8"))
		if jsonResponse.get('active') == True:
			return True
		else:
			return False

	def req(self, requisition, gateway):
		conn = http.client.HTTPSConnection(self.address[gateway], 4000)
		header = {'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
		body = 'req=' + requisition
		conn.request('POST', '/search', body, header)
		response = conn.getresponse()
		return response.read().decode("utf-8")


#Test
#Connector().checkToken("toke")
